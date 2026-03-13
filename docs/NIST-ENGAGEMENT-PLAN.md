# EMILIA Protocol — NIST Engagement Plan

**Target:** NIST Center for AI Standards and Innovation (CAISI) — AI Agent Standards Initiative
**Date:** March 2026
**Initiative URL:** https://www.nist.gov/caisi/ai-agent-standards-initiative

---

## 1. Context

NIST launched the AI Agent Standards Initiative on February 17, 2026 through CAISI. The initiative focuses on three pillars:

1. Facilitating industry-led development of agent standards
2. Fostering community-led open source protocol development
3. Advancing research in AI agent security and identity

EP directly addresses all three pillars — it is an industry-led, open-source protocol that provides trust and identity signals for AI agents.

---

## 2. Engagement Timeline

### MISSED — March 9, 2026
**CAISI RFI on AI Agent Security** — Response deadline passed.
Action: Prepare the response content anyway for future submissions and use it in the April 2 concept paper response.

### DEADLINE — April 2, 2026
**ITL AI Agent Identity and Authorization Concept Paper** — NCCoE project applying identity standards to enterprise agent use cases.

**This is the primary target.** EP's entity registration, API key authentication, and receipt-based reputation directly address the concept paper's scope: how to identify, manage, and authorize AI agents.

Action items:
- [ ] Draft response to concept paper (see Section 3 below)
- [ ] Reference EP as a complementary identity + reputation layer
- [ ] Include EP Spec v1.0 as supporting documentation
- [ ] Submit by April 1

### April 2-3, 2026
**MCP Dev Summit NA (NYC)** — AAIF event, not NIST, but NIST has indicated interest in MCP as a candidate for security/identity integration. EP's MCP server is directly relevant.

Action items:
- [ ] Submit speaker proposal for EP presentation (if CFP still open)
- [ ] Attend and network with NIST/CAISI representatives
- [ ] Distribute EP spec to NIST attendees

### April 2026 (dates TBD)
**CAISI Listening Sessions** — Sector-specific barriers to AI adoption (healthcare, finance, education).

Action items:
- [ ] Register for healthcare and finance listening sessions
- [ ] Prepare talking points on how EP addresses trust barriers in agent-mediated healthcare and financial transactions
- [ ] Emphasize: EP receipts contain no PHI/PII — scores are computed from transaction metadata only

### Ongoing
**NIST convenings and working groups** — CAISI will host additional workshops and technical convenings.

Action items:
- [ ] Monitor https://www.nist.gov/caisi for announcements
- [ ] Subscribe to CAISI mailing list
- [ ] Engage with NIST's National Cybersecurity Center of Excellence (NCCoE) on agent identity

---

## 3. Draft Response to ITL Concept Paper (AI Agent Identity and Authorization)

### Opening

EMILIA Protocol (EP) proposes a complementary approach to AI agent identity and authorization through reputation-based trust scoring. While traditional identity frameworks answer "who is this agent?", EP answers "should you trust this agent?" — a question that identity alone cannot resolve.

### Key Points to Make

**1. Agent Identity Is Necessary But Not Sufficient**

An AI agent can be properly authenticated and authorized but still be unreliable, dishonest, or low-quality. Identity tells you who is transacting. Reputation tells you whether to proceed.

EP provides the reputation layer: a 0-100 trust score computed from verified transaction receipts. Combined with identity standards, this gives organizations a complete picture: identity (who) + reputation (should I?).

**2. EP Addresses NIST's Three Pillars**

- **Standards**: EP Spec v1.0 is a formal protocol specification (receipt schema, scoring algorithm, API surface, verification flow). Apache-2.0 licensed.
- **Open source protocols**: The canonical implementation is fully open source. MCP server, TypeScript SDK, and Python SDK are available.
- **Security**: EP includes Sybil resistance (graph analysis, rate limiting, fraud detection), blockchain verification (Merkle proofs on Base L2), and append-only receipt ledgers.

**3. EP Complements Existing Identity Models**

EP does not replace identity and authorization standards — it layers on top of them:

| Layer | Standard | What It Provides |
|-------|----------|-----------------|
| Identity | OAuth 2.0, SAML, DID | Who is this agent? |
| Authorization | RBAC, ABAC, Capabilities | What can this agent do? |
| **Reputation** | **EP** | **Should you trust this agent?** |

An enterprise deploying AI agents can use EP to set minimum trust thresholds: "Only transact with agents that have an EMILIA Score above 70 and at least 5 verified receipts from 3+ unique counterparties."

**4. Healthcare and Financial Services Applications**

EP receipts contain no Protected Health Information (PHI) or Personally Identifiable Information (PII). Scores are computed from transaction metadata: delivery timing, price accuracy, return processing. This makes EP deployable in HIPAA-regulated and financial services environments without triggering data protection requirements on the scoring layer itself.

For healthcare: A hospital's procurement agent can check the EMILIA Score of a medical supply vendor's agent before placing orders — verifying delivery reliability and price integrity without exposing patient data.

For financial services: A lending platform's agent can verify the reputation of partner agents before sharing rate quotes — ensuring counterparty reliability through cryptographic receipts.

**5. Sybil Resistance and Fraud Prevention**

EP implements three layers of defense against fake entities and synthetic transactions:
- Registration friction (rate limiting, identity verification)
- Receipt graph analysis (closed-loop detection, thin-graph flagging, velocity monitoring)
- Protocol design (no self-scoring, rolling window, append-only ledger, behavioral signals)

This addresses NIST's concern about "confidence in the reliability of AI agents" with concrete, auditable mechanisms.

### Closing

EP is positioned as the trust and reputation layer for the emerging agent identity stack. We welcome NIST's guidance on how EP can align with the AI Agent Standards Initiative's goals and participate in future convenings and working groups.

---

## 4. Key Contacts at NIST

- **CAISI** (Center for AI Standards and Innovation) — caisi@nist.gov
- **NCCoE** (National Cybersecurity Center of Excellence) — for the identity/authorization concept paper
- **ITL** (Information Technology Laboratory) — co-leads the initiative with CAISI

---

## 5. Supporting Materials to Prepare

- [ ] EP Spec v1.0 (formatted as PDF for submission)
- [ ] One-page EP overview for government audience (no startup language)
- [ ] Technical brief: EP and AI Agent Identity (2-3 pages, maps EP to NIST pillars)
- [ ] Demo video: score lookup + receipt submission + Merkle verification
- [ ] AAIF proposal (cross-reference for credibility)

---

*Prepared March 2026 — EMILIA Protocol*
