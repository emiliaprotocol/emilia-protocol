# EMILIA Protocol — AAIF Working Group Proposal

**Proposed Working Group:** Trust Attestation for Agentic Commerce
**Submitted to:** Agentic AI Foundation (AAIF) / Linux Foundation
**Date:** March 2026
**Contact:** team@emiliaprotocol.ai
**License:** Apache-2.0
**Repository:** https://github.com/emiliaprotocol/emilia-protocol

---

## 1. Problem

The AAIF governs foundational projects that address how agents connect (MCP), execute (goose), and are guided (AGENTS.md). No current AAIF project addresses the question: **should you trust this counterparty?**

As AI agents autonomously handle commerce, the trust gap creates two failure modes:
- **Without trust signals:** Fraud at machine speed, no routing intelligence
- **With platform-controlled trust:** Centralized gatekeepers recreating the review system's conflicts of interest

Neither outcome serves the AAIF's mission of transparent, collaborative agentic AI infrastructure.

---

## 2. Proposal

We propose a **Trust Attestation Working Group** within AAIF to develop a vendor-neutral standard for portable, cross-platform counterparty trust in agentic commerce.

EMILIA Protocol (EP) is offered as the **initial reference implementation and draft specification** — not as a finished standard, but as a working starting point with a deployed canonical implementation.

**What we're NOT asking:** "AAIF, adopt our product."
**What we ARE asking:** "Let's build a neutral trust attestation standard together, starting from a working reference."

---

## 3. Scope — Core vs. Product

| Layer | What It Is | Governance |
|-------|-----------|-----------|
| **EP Core Spec** | Receipt schema, trust profile format, policy evaluation interface, context keys | AAIF working group deliverable |
| **EP Reference Implementation** | Canonical API, MCP server, SDKs | Open source, community-maintained |
| **EP Product Surfaces** | Leaderboard, explorer, entity profiles, landing page | Separate from the spec — not AAIF scope |

---

## 4. What the Spec Defines (EP Core RFC v1.1)

1. **Trust Receipt Schema** — Append-only, cryptographically hashed transaction records with mandatory `transaction_ref`, optional context keys (`task_type`, `category`, `geo`, `modality`, `value_band`, `risk_class`)
2. **Trust Profile** — The primary protocol output. Multi-dimensional: behavioral rates (completion, retry, abandon, dispute), per-signal breakdowns, consistency, anomaly alerts, confidence levels
3. **Trust Policies** — Portable decision frameworks. Agents evaluate counterparties against structured policies, not raw score thresholds. Built-in: `strict`, `standard`, `permissive`, `discovery`
4. **Receipt Weighting** — Three-factor: submitter credibility × time decay × graph health. Effective-evidence dampening prevents Sybil attacks
5. **Establishment & Confidence** — Historical establishment (permanent, all receipts) separated from current confidence (rolling window). Two distinct protocol objects
6. **Sybil Resistance** — 4 layers: IP-based rate limiting, graph analysis (closed-loop/cluster/thin-graph penalties), submitter credibility (unestablished = 0.1x), effective-evidence dampening
7. **Cryptographic Integrity** — Canonical JSON with sorted keys, SHA-256 receipt chains, Merkle anchoring, DB immutability triggers

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
| Core specification (EP-CORE-RFC v1.1) | Complete — behavioral-first, trust-profile-centric |
| Trust profile endpoint (`GET /api/trust/profile/:entityId`) | Deployed — canonical read surface |
| Policy evaluation (`POST /api/trust/evaluate`) | Deployed — 4 built-in + custom policies |
| Canonical receipt pipeline (`createReceipt()`) | Deployed — unified path for all receipt ingestion |
| Behavioral-first scoring (v2) | Deployed — behavioral 40%, consistency 20% |
| Effective-evidence Sybil resistance | Deployed — JS + SQL, dampens toward 50 based on weighted evidence |
| Graph weight in scoring path | Deployed — closed-loop 0.4x, cluster 0.1x + blocked |
| Context keys on receipts | Deployed — task_type, category, geo, modality, value_band |
| Current vs historical confidence separation | Deployed — two distinct objects in API |
| Receipt immutability (DB triggers) | Deployed — content changes rejected, anchor metadata allowed |
| Canonical JSON hashing (cross-language) | Deployed — sorted keys, deterministic |
| Rate limiting (Upstash Redis + fallback) | Deployed — all API routes via middleware |
| MCP server (6 tools) | Published on npm |
| TypeScript + Python SDKs | Published on npm + PyPI |
| Test suites (v1 + v2 scoring, policy evaluation) | Complete |
| NIST ITL Concept Paper | Prepared (April 2 deadline) |

---

## 7. Why Neutral Governance Matters

A trust layer controlled by any single platform would be inherently conflicted — they are merchants themselves. Amazon can't score Amazon sellers neutrally. Google can't score UCP merchants neutrally. OpenAI can't score ACP participants neutrally.

Under AAIF governance:
- No single company can manipulate scoring to favor their products
- The algorithm remains open source and auditable
- Multiple independent implementations can emerge
- Conformance testing ensures interoperability

---

## 8. Constitutional Principle

EP operates under one governing doctrine:

**EP must never make trust more powerful than appeal.**

If EP can influence routing, access, or conversion, then every negative trust effect must be explainable, challengeable, and reversible. The v4 architecture roadmap includes:

- **Provenance tiers** — classifying attestations from self-attested (0.05x) through bilateral (0.45x) to oracle-verified (1.0x), so evidence quality shapes trust more than any formula
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
- **Deliverables:** EP Core Spec v2.0, conformance test suite, ACP trust extension, Shopify reference integration
- **Timeline:** Spec finalized Q3 2026, conformance tests Q4 2026
- **Meetings:** Biweekly, open to all AAIF members

---

## 11. Immediate Next Steps

1. Present at MCP Dev Summit NA (April 2-3, NYC)
2. Submit NIST ITL Concept Paper (April 2 deadline)
3. Publish EP Core RFC v1.1 as standalone working group deliverable
4. Launch Shopify DTC reference integration (first external receipt source)
5. Solicit working group members from AAIF member organizations
6. First working group meeting Q2 2026

---

*EMILIA Protocol — A vendor-neutral trust attestation standard for agentic commerce.*
*Trust profiles, not scores. Policies, not thresholds. Due process, not silent mutation.*
*Compatible with ACP. Usable through MCP. Open source under Apache 2.0.*
