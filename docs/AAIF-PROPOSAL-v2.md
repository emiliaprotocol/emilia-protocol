# EMILIA Protocol — AAIF Working Group Proposal

**Proposed Working Group:** Trust Evaluation and Appeals for Machine Counterparties and Software
**Submitted to:** Agentic AI Foundation (AAIF) / Linux Foundation
**Date:** March 2026
**Contact:** team@emiliaprotocol.ai
**License:** Apache-2.0
**Repository:** https://github.com/emiliaprotocol/emilia-protocol

---

## 1. The Missing Layer

MCP defines how agents connect to tools. A2A defines how agents communicate. UCP and ACP define how agents transact. No standard defines how any of these principals should decide whether to trust each other.

This is not a gap. It is the gap. Without portable trust evaluation:
- Agents and systems cannot make safe autonomous or semi-autonomous decisions about counterparties, plugins, software, or services without a portable trust layer
- Platforms become trust gatekeepers by default — recreating the conflicts of interest that corrupted every previous trust system
- There is no due process when trust is wrong — no appeal, no explanation, no recourse

The AAIF's mission is transparent, collaborative agentic AI infrastructure. Trust evaluation with built-in due process is a precondition for that mission, not a feature.

---

## 2. Proposal

We propose a **Trust Evaluation and Appeals Working Group** within AAIF to develop the vendor-neutral standard for portable trust across counterparties, software, and machine actors.

EMILIA Protocol (EP) is offered as the **initial reference implementation and draft specification** — not as a finished standard, but as the most complete working starting point available:
- A deployed canonical implementation (emiliaprotocol.ai)
- CI-backed automated checks across 28 test files, 670 automated checks (JS + Python conformance) including adversarial, end-to-end, and conformance replay
- Cross-language conformance verification (JavaScript + Python)
- An MCP server with 24 MCP tools
- Install preflight for software entities (GitHub Apps, MCP servers, npm packages)
- A dispute and human appeal system with constitutional due process guarantees
- Zero-knowledge proofs for privacy-preserving trust attestation — entities prove score thresholds without revealing counterparties (critical for healthcare, legal, finance participation)
- Trust-graph dispute adjudication — disputes resolved by voucher network, not operators (adversarially resistant)
- Attribution chain standard — Principal→Agent→Tool chain with verified human accountability
- Delegation judgment scoring — first standard to score human delegation quality to AI agents
- Auto-receipt generation — passive behavioral data accumulation from MCP tool calls (opt-in)

**What we're NOT asking:** "AAIF, adopt our product."
**What we ARE asking:** "Let's build a neutral trust evaluation standard together, starting from a working reference."

---

## 3. Scope — Core vs. Product

| Layer | What It Is | Governance |
|-------|-----------|-----------|
| **EP Core Spec** | Receipt schema, trust profile format, policy evaluation interface, context keys | AAIF working group deliverable |
| **EP Reference Implementation** | Canonical API, MCP server, conformance suite | Open source, community-maintained |
| **EP Product Surfaces** | Leaderboard, explorer, entity profiles, landing page | Separate from the spec — not AAIF scope |

---

## 4. What the Spec Defines (EP Core RFC v1.0 — 17 sections)

1. **Trust Receipt Schema** — Append-only, cryptographically hashed transaction records with mandatory `transaction_ref`, optional context keys (`task_type`, `category`, `geo`, `modality`, `value_band`, `risk_class`)
2. **Trust Profile** — The primary protocol output. Multi-dimensional: behavioral rates (completion, retry, abandon, dispute), per-signal breakdowns, consistency, anomaly alerts, confidence levels
3. **Trust Policies** — Portable decision frameworks. Agents and systems evaluate counterparties, software, and machine actors against structured policies, not arbitrary numeric thresholds. Built-in: `strict`, `standard`, `permissive`, `discovery`
4. **Receipt Weighting** — Four-factor: submitter credibility × time decay × graph health × provenance tier. Effective-evidence dampening prevents Sybil attacks
5. **Establishment & Confidence** — Historical establishment (permanent, all receipts) separated from current confidence (rolling window). Two distinct protocol objects
6. **Sybil Resistance** — 4 layers: IP-based rate limiting, graph analysis (closed-loop/cluster/thin-graph penalties), submitter credibility (unestablished = 0.1x), effective-evidence dampening
7. **Cryptographic Integrity** — Canonical JSON with sorted keys, SHA-256 receipt chains, Merkle anchoring, DB immutability triggers
8. **Zero-Knowledge Trust Proofs** — HMAC-SHA256 commitment-based proofs allowing entities to prove trust threshold claims without revealing counterparty identities or transaction contents. Enables participation by privacy-constrained industries.
9. **Attribution Chain** — Verifiable Principal→Agent→Tool attribution records. Weak principal signal (0.15x) for delegation judgment. Requires both `delegation_id` and `principal_id` for attribution to prevent unverifiable claims.
10. **Trust-Graph Adjudication** — Dispute resolution by high-confidence network vouchers. 48-hour procedural window before graph consulted. Accused entity receipts weighted 0.4x in own adjudication to prevent self-serving outcomes.
11. **Auto-Receipt Generation** — Opt-in behavioral data capture from MCP tool calls. Privacy-by-default: sensitive fields redacted, provenance marked unilateral, no raw output stored.

---

## 5. Integration with AAIF Projects

| AAIF Project | Integration Point |
|-------------|------------------|
| **MCP** | EP MCP tools: `ep_trust_profile`, `ep_trust_evaluate`, `ep_submit_receipt` |
| **ACP** | EP trust proofs attached to ACP payment flows: "Before completing payment, evaluate merchant against trust policy" |
| **A2A** | EP trust context in A2A Agent Cards for routing decisions |
| **goose** | Goose agents query EP trust profiles before executing transactions |

EP is a **composable layer**, not a competing protocol. It attaches to ACP, is usable through MCP, and informs A2A routing.

---

## 6. Current Maturity

| Component | Status |
|-----------|--------|
| Core specification (EP-CORE-RFC v1.0, 17 sections) | Complete — behavioral-first, trust-profile-centric |
| Trust profile endpoint (`GET /api/trust/profile/:entityId`) | Deployed — canonical read surface |
| Policy evaluation (`POST /api/trust/evaluate`) | Deployed — 4 built-in + custom JSONB policies, **context-aware** |
| Context-aware trust evaluation | Deployed — filters receipts by context, falls back to global when sparse |
| Canonical receipt pipeline (`createReceipt()`) | Deployed — unified path for all receipt ingestion |
| Behavioral-first scoring (v2) | Deployed — behavioral 40%, consistency 25%, weights sum to 1.00 |
| Effective-evidence Sybil resistance | Deployed — JS + SQL, dampens toward 50 based on weighted evidence |
| Graph weight in scoring path | Deployed — closed-loop 0.4x, cluster 0.1x + blocked |
| Context keys on receipts | Deployed — task_type, category, geo, modality, value_band, risk_class |
| Current vs historical confidence separation | Deployed — two distinct objects in all API surfaces |
| Policy-native needs | Deployed — needs accept JSONB trust policies, claim evaluates against them |
| Confidence-aware search and leaderboard | Deployed — rank by confidence or effective evidence; filter by min_confidence |
| Receipt immutability (DB triggers) | Deployed — content changes rejected, anchor metadata allowed |
| Canonical JSON hashing (cross-language) | Deployed — sorted keys, deterministic, context included |
| Identity-aware write throttling | Deployed — API key prefix + IP on writes, IP-only on reads |
| Server-derived owner identity | Deployed — SHA-256 of client IP, not caller-supplied |
| MCP server (24 tools, context-aware) | Published on npm — trust-profile-first, context forwarded |
| SDKs | Planned / optional future implementations |
| Test suites (28 test files, 670 automated checks, CI-backed) | Complete — scoring, trust profiles, protocol surfaces, adversarial resistance, end-to-end flows, conformance |
| NIST ITL Concept Paper | Prepared (April 2 deadline) |
| Shopify DTC integration spec | Complete — webhook mapping, receipt mapping, MVP roadmap |

---

## 7. Why Neutral Governance Matters

**Tool access is not trust.** MCP standardizes how systems connect to tools; it does not decide whether those tools should be trusted.

**Commerce flow is not trust.** ACP/UCP/AP2 can structure transactions and payments; they do not provide a portable basis for judging counterparties or software.

**Identity is not trust.** Knowing who an actor is and what it is allowed to do does not answer whether it should be trusted in a given context.

**Trust without appeal is dangerous.** If trust can influence installation, routing, or conversion, then it needs challenge, response, adjudication, and reversal.

A trust layer controlled by any single platform would be inherently conflicted — they are merchants themselves. Amazon can't evaluate Amazon sellers neutrally. Google can't evaluate UCP merchants neutrally. OpenAI can't evaluate ACP participants neutrally.

Under AAIF governance:
- No single company can manipulate trust to favor their products
- The algorithm remains open source and auditable
- Multiple independent implementations can emerge
- Conformance testing ensures interoperability

---

## 8. Constitutional Principle

EP operates under one governing doctrine:

**EP must never make trust more powerful than appeal.**

If EP can influence routing, access, or conversion, then every negative trust effect must be explainable, challengeable, and reversible. The v4 architecture roadmap includes:

- **Provenance tiers** — classifying receipts, evidence, and verified trust events from self-attested (0.05x) through bilateral (0.45x) to oracle-verified (1.0x), so evidence quality shapes trust more than any formula
- **Due-process lifecycle** — submitted → challenged → under review → resolved/reversed → superseded. Corrections are append-only. Nothing is erased.
- **Context keys** — trust scoped to task type, category, geography, modality, and value band. Global trust is a fallback prior, not the primary representation.
- **Relationship trust** — pairwise trust with hierarchical backoff: A's experience with B in context C, falling back through broader contexts to global priors.

These are not hypothetical. Context keys are already deployed in the receipt schema. The constitutional document (EP Constitution v4) is available for working group review.

---

## 9. Initial Wedge: DTC Commerce on Shopify

EP's first production vertical targets DTC merchants on Shopify — a category where delivery accuracy, product-as-described, price integrity, and return processing are high-value, measurable trust signals.

The integration architecture: Shopify webhooks (orders/paid, fulfillments, refunds, returns) → normalized merchant event ledger → canonical EP receipts with structured claims and evidence references.

This produces machine-readable trust profiles that AI shopping agents can evaluate before checkout — turning a DTC store into an agent-trustable merchant before AI agents become a major sales channel.

A complete Shopify integration spec (webhook mapping, receipt mapping, public trust surfaces, MVP roadmap) is prepared and available for working group review.

---

## 10. Proposed Working Group Structure

- **Chair:** EMILIA Protocol (initial), rotating annually
- **Members:** Open to any AAIF member organization
- **Deliverables:** EP Core Spec v2.0, EP-IX Identity Continuity Extension, conformance test suite, ACP trust extension, Shopify reference integration
- **Timeline:** Spec finalized Q3 2026, conformance tests Q4 2026
- **Meetings:** Biweekly, open to all AAIF members

---

## 11. Immediate Next Steps

1. Present at MCP Dev Summit NA (April 2-3, NYC)
2. Submit NIST ITL Concept Paper (April 2 deadline) — include EP Core RFC v1.0
3. Publish EP Core RFC v1.0 (17 sections) as standalone working group deliverable
4. Launch Shopify DTC reference integration (first external receipt source)
5. Solicit working group members from AAIF member organizations
6. First working group meeting Q2 2026

---

*EMILIA Protocol — Portable trust evaluation and appeals for counterparties, software, and machine actors.*
*Trust profiles, not scores. Policies, not thresholds. Due process, not silent mutation.*
*Compatible with ACP. Usable through MCP. Open source under Apache 2.0.*
