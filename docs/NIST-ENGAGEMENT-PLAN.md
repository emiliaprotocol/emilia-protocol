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

EP directly addresses all three pillars — it is an industry-led, open-source protocol that provides portable, policy-evaluable trust attestation for AI agents.

---

## 2. Engagement Timeline

### MISSED — March 9, 2026
**CAISI RFI on AI Agent Security** — Response deadline passed.
Action: Prepare the response content anyway for future submissions and use it in the April 2 concept paper response.

### DEADLINE — April 2, 2026
**ITL AI Agent Identity and Authorization Concept Paper** — NCCoE project applying identity standards to enterprise agent use cases.

**This is the primary target.** EP's entity registration, trust profiles, policy evaluation, and context-aware receipts directly address the concept paper's scope: how to identify, manage, and authorize AI agents.

Action items:
- [ ] Draft response to concept paper (see Section 3 below)
- [ ] Reference EP as a complementary trust attestation layer
- [ ] Include EP Core RFC v1.1 as supporting documentation
- [ ] Submit by April 1

### April 2-3, 2026
**MCP Dev Summit NA (NYC)** — AAIF event, not NIST, but NIST has indicated interest in MCP as a candidate for security/identity integration. EP's MCP server (trust-profile-first, context-aware) is directly relevant.

Action items:
- [ ] Attend and network with NIST/CAISI representatives
- [ ] Distribute EP Core RFC v1.1 to NIST attendees

### April 2026 (dates TBD)
**CAISI Listening Sessions** — Sector-specific barriers to AI adoption (healthcare, finance, education).

Action items:
- [ ] Register for healthcare and finance listening sessions
- [ ] Prepare talking points on how EP addresses trust barriers in agent-mediated healthcare and financial transactions
- [ ] Emphasize: EP receipts contain no PHI/PII — trust profiles are computed from transaction metadata only

### Ongoing
**NIST convenings and working groups** — CAISI will host additional workshops and technical convenings.

Action items:
- [ ] Monitor https://www.nist.gov/caisi for announcements
- [ ] Subscribe to CAISI mailing list
- [ ] Engage with NIST's National Cybersecurity Center of Excellence (NCCoE) on agent identity

---

## 3. Draft Response to ITL Concept Paper (AI Agent Identity and Authorization)

### Opening

EMILIA Protocol (EP) proposes a complementary approach to AI agent identity and authorization through trust attestation. While traditional identity frameworks answer "who is this agent?", EP answers "should you trust this agent?" — a question that identity alone cannot resolve.

### Key Points to Make

**1. Agent Identity Is Necessary But Not Sufficient**

An AI agent can be properly authenticated and authorized but still be unreliable, dishonest, or low-quality. Identity tells you who is transacting. Trust attestation tells you whether to proceed.

EP provides the trust layer: multi-dimensional trust profiles computed from verified transaction receipts, evaluated against configurable policies. Combined with identity standards, this gives organizations a complete picture: identity (who) + trust (should I?).

**2. EP Addresses NIST's Three Pillars**

- **Standards**: EP Core RFC v1.1 is a formal protocol specification — receipt schema with context keys, behavioral-first scoring, trust profile format, policy evaluation interface, canonical establishment rules. Apache-2.0 licensed.
- **Open source protocols**: The canonical implementation is fully open source. MCP server (8 tools, context-aware) and a conformance-backed reference implementation are published. 3+ test suites cover core protocol behavior.
- **Security**: EP includes 4-layer Sybil resistance (effective-evidence dampening, graph analysis, submitter credibility, identity-aware rate limiting), blockchain verification (Merkle proofs on Base L2), and append-only receipt ledgers with DB immutability triggers.

**3. EP Complements Existing Identity Models**

EP does not replace identity and authorization standards — it layers on top of them:

| Layer | Standard | What It Provides |
|-------|----------|-----------------|
| Identity | OAuth 2.0, SAML, DID | Who is this agent? |
| Authorization | RBAC, ABAC, Capabilities | What can this agent do? |
| **Trust** | **EP** | **Should you trust this agent for this task in this context?** |

An enterprise deploying AI agents can use EP to evaluate counterparties against trust policies: "Evaluate this vendor agent against our 'strict' policy for medical supplies in US-East" → pass/fail with specific failure reasons, behavioral rates, confidence level, and context used.

**4. Healthcare and Financial Services Applications**

EP receipts contain no Protected Health Information (PHI) or Personally Identifiable Information (PII). Trust profiles are computed from transaction metadata: delivery timing, price accuracy, return processing, behavioral outcomes. This makes EP deployable in HIPAA-regulated and financial services environments without triggering data protection requirements.

For healthcare: A hospital's procurement agent evaluates a medical supply vendor's trust profile before placing orders — checking delivery accuracy, dispute rate, and confidence level for the specific category and geography, without exposing patient data.

For financial services: A lending platform's agent evaluates partner agents against a strict trust policy before sharing rate quotes — ensuring counterparty reliability through context-aware, policy-based trust assessment.

**5. Sybil Resistance and Fraud Prevention**

EP implements four layers of defense against fake entities and synthetic transactions:
- Identity-aware rate limiting (API key prefix + IP on writes, Upstash Redis)
- Receipt graph analysis (closed-loop 0.4x, thin-graph 0.5x, cluster 0.1x + blocked)
- Submitter credibility (unestablished entities carry 0.1x weight regardless of claim content)
- Effective-evidence dampening (scores pulled toward 50 until weighted evidence exceeds threshold)

This addresses NIST's concern about "confidence in the reliability of AI agents" with concrete, auditable, mathematically testable mechanisms.

### Closing

EP is positioned as the trust attestation layer for the emerging agent identity stack. Its constitutional principle — trust must never be more powerful than appeal — ensures that as EP influences routing decisions, every negative effect remains explainable, challengeable, and reversible.

We welcome NIST's guidance on how EP can align with the AI Agent Standards Initiative's goals and participate in future convenings and working groups.

---

## 4. Key Contacts at NIST

- **CAISI** (Center for AI Standards and Innovation) — caisi@nist.gov
- **NCCoE** (National Cybersecurity Center of Excellence) — for the identity/authorization concept paper
- **ITL** (Information Technology Laboratory) — co-leads the initiative with CAISI

---

## 5. Supporting Materials to Prepare

- [ ] EP Core RFC v1.1 (formatted as PDF for submission)
- [ ] One-page EP overview for government audience (no startup language)
- [ ] Technical brief: EP and AI Agent Identity (2-3 pages, maps EP to NIST pillars)
- [ ] Demo video: trust profile lookup + policy evaluation + context-aware receipts + Merkle verification
- [ ] AAIF proposal (cross-reference for credibility)
- [ ] Shopify DTC integration spec (demonstrates real-world vertical application)

---

*Prepared March 2026 — EMILIA Protocol*
