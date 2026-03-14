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

EMILIA Protocol (EP) is offered as the **initial reference implementation and draft specification** for this working group — not as a finished standard, but as a working starting point with a deployed canonical implementation.

**What we're NOT asking:** "AAIF, adopt our product."
**What we ARE asking:** "Let's build a neutral trust attestation standard together, starting from a working reference."

---

## 3. Scope — Core vs. Product

Following AAIF precedent (MCP is a spec, not an app), we propose separating EP into:

| Layer | What It Is | Governance |
|-------|-----------|-----------|
| **EP Core Spec** | Receipt schema, scoring algorithm interface, score proof format | AAIF working group deliverable |
| **EP Reference Implementation** | Canonical API, MCP server, SDKs | Open source, community-maintained |
| **EP Product Surfaces** | Leaderboard, explorer, entity profiles, landing page | Separate from the spec — not AAIF scope |

The working group owns the **spec and proof format**. The reference implementation and product surfaces remain community projects that implement the spec.

---

## 4. What the Spec Defines

The EP Core Spec (2 pages) defines:

1. **Trust Receipt Schema** — A standardized format for recording transaction outcomes between agents/merchants
2. **Scoring Algorithm Interface** — The 6-signal weighted formula (open source, auditable, deterministic)
3. **Score Proof Format** — How an entity proves its trust score to a counterparty (compatible with ACP payment flows and MCP tool responses)
4. **Verification Flow** — Merkle tree batching + blockchain anchoring for independent verification

The spec does NOT define: leaderboards, entity profiles, explorer UIs, registration flows, or any application-layer concerns.

---

## 5. Integration with AAIF Projects

| AAIF Project | Integration Point |
|-------------|------------------|
| **MCP** | EP MCP tools: `ep_score_lookup`, `ep_submit_receipt`, `ep_verify_receipt` — any MCP client can check trust |
| **ACP** | EP trust proofs attached to ACP payment flows: "Before completing payment, verify merchant EP score ≥ 70" |
| **A2A** | EP score field in A2A Agent Cards for routing decisions |
| **goose** | Goose agents query EP scores before executing transactions |

EP is designed as a **composable layer**, not a competing protocol. It attaches to ACP, is usable through MCP, and informs A2A routing.

---

## 6. Current Maturity

| Component | Status |
|-----------|--------|
| Protocol specification (EP-SPEC v1.0) | Complete (523 lines, 11 sections) |
| Canonical implementation (15 API endpoints) | Deployed at emiliaprotocol.ai |
| Scoring algorithm (6 signals, submitter weighting, time decay) | Complete, Sybil-resistant |
| Score confidence states (5 levels) | Complete |
| MCP server (6 tools) | Published on npm |
| TypeScript SDK | Published on npm |
| Python SDK | Published on PyPI |
| Blockchain verification (Merkle + Base L2) | Complete |
| Sybil resistance (4 layers) | Complete |
| NIST ITL Concept Paper submission | Prepared (April 2 deadline) |

---

## 7. Why Neutral Governance Matters

A trust layer controlled by any single platform would be inherently conflicted — they are merchants themselves. Amazon can't score Amazon sellers neutrally. Google can't score UCP merchants neutrally. OpenAI can't score ACP participants neutrally.

Under AAIF governance:
- No single company can manipulate scoring to favor their products
- The algorithm remains open source and auditable
- Multiple independent implementations can emerge
- Conformance testing ensures interoperability

---

## 8. Proposed Working Group Structure

- **Chair:** EMILIA Protocol (initial), rotating annually
- **Members:** Open to any AAIF member organization
- **Deliverables:** EP Core Spec v1.0, conformance test suite, ACP trust extension draft
- **Timeline:** Spec finalized Q3 2026, conformance tests Q4 2026
- **Meetings:** Biweekly, open to all AAIF members

---

## 9. Immediate Next Steps

1. Present at MCP Dev Summit NA (April 2-3, NYC) — networking, not speaking (CFP closed)
2. Submit NIST ITL Concept Paper (April 2 deadline)
3. Publish EP Core Spec as standalone RFC
4. Solicit working group members from AAIF member organizations
5. First working group meeting Q2 2026

---

*EMILIA Protocol — A vendor-neutral trust attestation standard for agentic commerce.*
*Compatible with ACP. Usable through MCP. Open source under Apache 2.0.*
