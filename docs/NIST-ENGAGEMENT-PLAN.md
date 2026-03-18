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

EMILIA Protocol (EP) contributes to this conversation as an open-source protocol specification for trust evaluation, trust decisions, and adverse decision review in agent systems. EP demonstrates one approach to the trust evaluation gap that exists between identity/authorization frameworks and operational deployment of AI agents.

---

## 2. EP Architecture for Standards Audiences

To support clear scoping in standards discussions, EP is organized into three layers:

### EP Core (candidate for standardization)
Three interoperable objects that define the minimal trust evaluation interface:

1. **Trust Receipt** — a portable, append-only behavioral event record with cryptographic integrity, provenance tier, and context keys
2. **Trust Profile** — a standardized read object summarizing observed trust state: confidence level, evidence depth, behavioral rates, provenance composition, anomaly flags, dispute summary
3. **Trust Decision** — a policy-evaluated result for a specific action and context, returning `allow`/`review`/`deny` with reasons, evidence sufficiency, policy reference, and appeal path

These three objects are what EP proposes as its contribution to agent identity and authorization standards. If a third party can implement these three objects and interoperate, the core standard is met.

### EP Extensions (important, not required for interoperability)
- Disputes and appeals lifecycle
- Delegation and attribution chain
- Domain-specific scoring
- Zero-knowledge trust proofs
- Auto-receipt generation
- Software install preflight adapters
- Voucher-based adjudication

### EP Product Surfaces (explicitly not in standard scope)
- Explorer and registry views
- Leaderboards and dashboards
- Managed adjudication workflows
- Hosted operator tooling

---

## 3. Mapping EP to Concrete NIST Concerns

EP can support five areas the AI Agent Standards Initiative has identified as in-scope:

### Identity: How agents identify themselves and their authorization chain
EP's Trust Profile provides a behavioral identity complement to cryptographic identity. Where OAuth, SAML, or DID answer "who is this agent?", a Trust Profile answers "what is the observed trust state of this agent for a given context?" The profile includes provenance composition, evidence depth, and anomaly detection — enabling receiving parties to evaluate counterparties beyond credential verification.

### Authorization: Delegation chains with verifiable principal accountability
EP's attribution chain extension records Principal-to-Agent-to-Tool delegation with verifiable accountability. Weak principal signals receive dampened weighting (0.15x) to avoid overstating unverified delegation claims. Both `delegation_id` and `principal_id` are required to prevent unverifiable attribution. This enables audit of human oversight quality in delegated agent actions.

### Auditability: Append-only receipt ledger with cryptographic integrity
Trust Receipts form an append-only behavioral record with HMAC-SHA256 integrity, provenance tier classification, and optional blockchain anchoring (Merkle proofs on Base L2). Database immutability triggers prevent retroactive modification. This can support the audit trail requirements that NIST has identified for accountable agent systems.

### Evidence: Multi-factor trust profiles based on observed behavior
Trust Profiles are computed from behavioral evidence — delivery rates, accuracy, dispute outcomes, response timing — not from reputation signals or self-reported claims. Effective-evidence dampening ensures that trust remains conservative until sufficient weighted evidence accumulates. Sybil resistance layers (graph analysis, submitter credibility weighting, rate limiting) protect evidence integrity.

### Adverse decision review: Explainability, challengeability, reversibility
EP's constitutional requirement states that any adverse trust effect must be explainable, challengeable, reviewable, and reversible when wrong. Trust Decisions include specific failure reasons, the policy applied, the evidence state at evaluation time, and a dispute/appeal path. This demonstrates one approach to the due process gap in current agent trust systems.

---

## 4. Mapping EP to NIST AI RMF Pillars

### Govern
- Policy-based trust evaluation: operators define trust policies with configurable thresholds, and Trust Decisions are evaluated against those policies — not against a single global score
- Human oversight via delegation judgment: the attribution chain extension enables auditing the quality of human delegation decisions over time
- Constitutional guarantee: adverse trust effects carry mandatory explainability and appeal paths

### Map
- Context-aware evaluation: Trust Decisions incorporate `task_type`, `geo`, `modality`, `value_band`, and `risk_class` as context keys
- The same entity can receive different Trust Decisions for different contexts, reflecting that trust is not a fixed property but a context-dependent evaluation

### Measure
- Behavioral rates: delivery, accuracy, dispute, return, and other domain-relevant rates computed from receipt evidence
- Provenance composition: receipts are classified by provenance tier (direct observation, verified integration, self-reported) with differential weighting
- Effective evidence: dampening toward baseline until weighted evidence exceeds configurable thresholds
- Anomaly detection: flags for unusual patterns in receipt submission, timing, or behavioral distribution

### Manage
- Disputes: structured dispute lifecycle with evidence submission, response windows, and resolution
- Appeals: adverse decisions can be formally challenged with additional evidence
- Weight dampening: anomalous or low-provenance evidence is dampened rather than excluded, preserving auditability
- Reversal propagation: when a dispute is resolved in favor of the subject, affected Trust Decisions can be re-evaluated

---

## 5. Engagement Timeline

### MISSED — March 9, 2026
**CAISI RFI on AI Agent Security** — Response deadline passed.
Action: Prepare the response content for use in the April 2 concept paper response and future submissions.

### DEADLINE — April 2, 2026
**ITL AI Agent Identity and Authorization Concept Paper** — NCCoE project applying identity standards to enterprise agent use cases.

**This is the primary target.** The concept paper's scope — how to identify, manage, and authorize AI agents — directly intersects with EP's trust evaluation contribution.

Action items:
- [ ] Draft response to concept paper (see Section 6 below)
- [ ] Position EP Core's three objects as a trust evaluation contribution to the agent identity and authorization stack
- [ ] Include EP Core RFC v1.0 as supporting documentation
- [ ] Submit by April 1

### April 2-3, 2026
**MCP Dev Summit NA (NYC)** — AAIF event. NIST has indicated interest in MCP as a candidate for security/identity integration. EP's MCP server demonstrates trust-profile-first, context-aware evaluation as a complement to MCP tool invocation.

Action items:
- [ ] Attend and engage with NIST/CAISI representatives if present
- [ ] Distribute EP Core RFC v1.0 overview to relevant attendees
- [ ] Position EP as a trust evaluation layer that can support MCP security goals

### April 2026 (dates TBD)
**CAISI Listening Sessions** — Sector-specific barriers to AI adoption (healthcare, finance, education).

Action items:
- [ ] Register for healthcare and finance listening sessions
- [ ] Lead talking points with: "Agent systems handling sensitive workflows need trust evaluation that does not require disclosing interaction history"
- [ ] Healthcare talking point: EP's zero-knowledge trust proof extension enables entities to demonstrate trust thresholds (e.g., "confidence > 0.85 in healthcare domain, based on 50+ receipts") without revealing counterparty identities or transaction contents. This can support participation in HIPAA-sensitive workflows by enabling trust verification without counterparty disclosure.
- [ ] Finance talking point: The same ZK proof mechanism enables trust verification in financially regulated environments without exposing transaction-level detail. This can support privacy-sensitive agent participation when implemented with appropriate controls.
- [ ] Frame ZK proofs as "enabling participation in privacy-sensitive environments" — not as solving compliance

### Ongoing
**NIST convenings and working groups** — CAISI will host additional workshops and technical convenings.

Action items:
- [ ] Monitor https://www.nist.gov/caisi for announcements
- [ ] Subscribe to CAISI mailing list
- [ ] Engage with NIST's National Cybersecurity Center of Excellence (NCCoE) on agent identity

---

## 6. Draft Response to ITL Concept Paper (AI Agent Identity and Authorization)

### Opening

EMILIA Protocol (EP) offers a trust evaluation contribution to the agent identity and authorization conversation. Identity frameworks answer "who is this agent?" and authorization frameworks answer "what is it allowed to do?" EP demonstrates one approach to a question that identity and authorization alone do not resolve: "given this agent's observed behavioral history, should it be trusted for this task in this context?"

EP proposes three interoperable objects — Trust Receipt, Trust Profile, and Trust Decision — as a minimal trust evaluation layer that can complement identity and authorization standards in agent systems.

### Key Points

**1. Identity and Authorization Create a Trust Evaluation Gap**

An AI agent can be properly authenticated and authorized yet still be unreliable, inconsistent, or poorly suited for a specific context. Identity establishes who is transacting. Authorization establishes what is permitted. Trust evaluation assesses whether to proceed, based on observed behavioral evidence.

EP's three core objects address this gap:
- **Trust Receipt**: a portable behavioral event record with provenance classification and cryptographic integrity
- **Trust Profile**: a standardized summary of observed trust state, computed from receipt evidence
- **Trust Decision**: a policy-evaluated result with reasons, evidence sufficiency, and appeal path

| Layer | Examples | Question Answered |
|-------|----------|-------------------|
| Identity | OAuth 2.0, SAML, DID | Who is this agent? |
| Authorization | RBAC, ABAC, Capabilities | What can this agent do? |
| Trust Evaluation | EP Core objects | Should this agent be trusted for this task in this context? |

**2. EP Core Supports NIST's Three Initiative Pillars**

- **Standards**: EP Core RFC v1.0 is a formal protocol specification defining receipt schema, trust profile format, trust decision interface, provenance tiers, and policy evaluation rules. Apache-2.0 licensed.
- **Open source protocols**: A reference implementation is published with REST API, MCP server, and conformance test suite. The reference implementation is a working starting point, not the standard itself.
- **Security and identity**: EP includes Sybil resistance mechanisms (effective-evidence dampening, graph analysis, submitter credibility, rate limiting) and append-only receipt integrity. These can support the security requirements NIST has identified for agent systems.

**3. EP Complements — Does Not Replace — Identity and Authorization Standards**

EP layers on top of existing identity and authorization infrastructure. It does not propose alternatives to OAuth, SAML, DID, RBAC, or ABAC. Instead, EP provides a trust evaluation step that consumes identity and authorization context and returns a structured decision with reasons and recourse.

**4. Privacy-Sensitive Environments**

EP can support privacy-sensitive environments when implemented with appropriate controls:

- Trust Receipts record behavioral metadata (delivery timing, accuracy, dispute outcomes) — not transaction contents or personally identifiable information
- The zero-knowledge trust proof extension enables entities to demonstrate trust thresholds without revealing counterparty identities or interaction history
- This can enable agent participation in workflows where trust verification is needed but counterparty disclosure is not permitted

**5. Adverse Decision Review**

EP's constitutional requirement ensures that trust evaluation does not become unaccountable control infrastructure. Any adverse trust effect must be:
- **Explainable**: Trust Decisions include the specific reasons for denial or review, the policy applied, and the evidence state
- **Challengeable**: a dispute path is included in every adverse Trust Decision
- **Reviewable**: disputes follow a structured lifecycle with evidence submission and response windows
- **Reversible**: when a dispute is resolved in favor of the subject, affected decisions can be re-evaluated

### Closing

EP is one contribution to the standards conversation around trust evaluation for AI agents. Its three core objects — Trust Receipt, Trust Profile, and Trust Decision — demonstrate a minimal interoperable approach to the trust evaluation gap between identity/authorization and operational deployment.

We welcome NIST's guidance on how EP can participate in the AI Agent Standards Initiative's future convenings, working groups, and standards development processes.

---

## 7. Key Contacts at NIST

- **CAISI** (Center for AI Standards and Innovation) — caisi@nist.gov
- **NCCoE** (National Cybersecurity Center of Excellence) — for the identity/authorization concept paper
- **ITL** (Information Technology Laboratory) — co-leads the initiative with CAISI

---

## 8. Supporting Materials to Prepare

- [ ] EP Core RFC v1.0 (formatted as PDF for submission)
- [ ] Two-page EP overview for standards audience: problem statement, three core objects, AI RMF mapping, constitutional guarantee
- [ ] Technical brief: EP and AI Agent Identity (2-3 pages, maps EP Core objects to NIST identity/authorization scope)
- [ ] Conformance test summary: what a third-party implementation must pass to interoperate
- [ ] Reference implementation overview: REST API, MCP server, test suite (clearly labeled as reference, not the standard)

---

*Prepared March 2026 — EMILIA Protocol*
