# EP Compliance Mapping: EU Artificial Intelligence Act

**Version:** 1.0  
**Date:** 2026-04-07  
**Protocol:** EMILIA Protocol v1.0  
**Regulation:** EU AI Act (Regulation 2024/1689, effective August 2025)

---

## Scope

This mapping covers EP's ability to help operators satisfy obligations under the EU AI Act, with focus on **high-risk AI systems** (Title III, Chapter 2) and **general-purpose AI** (Title VIII-A). EP is not an AI system itself — it is the trust enforcement infrastructure that AI systems use to demonstrate compliance.

---

## Article 9 — Risk Management System

| Requirement | EP Implementation |
|-------------|-------------------|
| 9(1): Establish a risk management system | EP provides a structured, auditable trust evaluation pipeline (`protocolWrite()`) through which every high-risk action passes. System is continuous, documented, and versioned. |
| 9(2)(a): Identify and analyze known risks | EP Eye observation layer classifies risk patterns by domain. Trust profiles track anomaly flags, negative outcome rates, and provenance quality. |
| 9(2)(b): Estimate and evaluate risks | EP Trust Decisions produce `allow`/`review`/`deny` with evidence sufficiency metrics, domain scores, and confidence levels. |
| 9(2)(c): Evaluate risks from reasonably foreseeable misuse | EP adversarial test suite: 116 red team cases including Sybil attacks, trust farming, collusion detection, and replay attempts. |
| 9(2)(d): Adopt risk management measures | EP four-layer enforcement: Eye → Handshake → Signoff → Commit. Each layer has independent controls, audit trails, and enforcement capabilities. |
| 9(4): Testing to identify appropriate measures | EP: 670+ automated tests, TLA+ model checking (7,857 states), Alloy relational verification, property-based testing with fast-check. |
| 9(5): Testing against previously defined metrics | EP conformance test suite with deterministic fixtures, mutation testing (80%+ kill), and cross-language hash verification. |
| 9(7): Risk management throughout AI system lifecycle | EP Trust Profiles are continuously updated. Score history tracks changes. Dispute lifecycle enables ongoing risk correction. |

---

## Article 10 — Data and Data Governance

| Requirement | EP Implementation |
|-------------|-------------------|
| 10(2): Training data quality | EP receipt provenance tiers (6 levels, 0.3x–1.0x weight) ensure trust evidence quality is tracked and weighted. |
| 10(2)(f): Examination for possible biases | EP Sybil resistance (graph analysis, submitter credibility dampening) prevents manipulation of the trust evidence corpus. |
| 10(3): Data governance practices | EP write guard enforces that only the canonical write layer can modify trust-bearing tables. Append-only event log. |

---

## Article 11 — Technical Documentation

| Requirement | EP Implementation |
|-------------|-------------------|
| 11(1): Technical documentation maintained | EP: PROTOCOL-STANDARD.md (17 sections), architecture docs (18 files), API documentation (8 files), formal specifications (TLA+, Alloy). |
| 11(1): Documentation kept up to date | EP PIP process governs all protocol changes. Version-controlled documentation in git. CI enforces doc consistency. |

---

## Article 12 — Record-Keeping (Logging)

| Requirement | EP Implementation |
|-------------|-------------------|
| 12(1): Automatic recording of events | EP `protocol_events` table: append-only log of every trust-changing state transition. `handshake_events`: per-ceremony audit trail. `audit_events`: operator-level log. |
| 12(2): Logging enables traceability | EP protocol events include: `event_id`, `aggregate_type`, `aggregate_id`, `command_type`, `parent_event_hash`, `payload_hash`, `actor_authority_id`, `idempotency_key`, `created_at`. Chain-linked for tamper detection. |
| 12(3): Logging throughout lifetime | EP events are never deleted. Immutability enforced by database triggers and write guard. SIEM forwarder for external log aggregation. |

---

## Article 13 — Transparency

| Requirement | EP Implementation |
|-------------|-------------------|
| 13(1): Sufficient transparency for interpretation | EP Trust Decisions include `reasons` array (human-readable), `policy_used`, `evidence_sufficient` flag, and `appeal_available` indicator. |
| 13(2): Accompanying instructions for use | EP: QUICK_START_INTEGRATION.md, SDK documentation, MCP server with 34 self-describing tools. |
| 13(3)(b)(ii): Level of accuracy and limitations | EP Trust Profiles include `confidence` level (5 tiers) and `evidence_depth`. Commitment proofs enable privacy-preserving accuracy attestation. |

---

## Article 14 — Human Oversight

| Requirement | EP Implementation |
|-------------|-------------------|
| 14(1): Human oversight measures | **EP Accountable Signoff**: named human must explicitly assume responsibility before high-risk action proceeds. Not optional — policy-enforced. |
| 14(2): Understanding AI system capabilities | EP Eye SHADOW mode: logs what enforcement would have done, enabling human review without blocking. |
| 14(3)(a): Monitor operations | EP Cloud dashboard: real-time handshake monitoring, signoff queue, event explorer. |
| 14(3)(b): Remain aware of automation bias | EP delegation judgment scoring measures how well humans oversee their AI agents. Poor delegation scores surface accountability gaps. |
| 14(4)(a): Correctly interpret output | EP Trust Decisions are structured, not opaque. Decision + reasons + evidence + policy + appeal path in every response. |
| 14(4)(b): Decide not to use the system | EP supports manual override: Signoff denial, Handshake revocation, Commit revocation — all with audit trail. |
| 14(4)(c): Override the output | EP dispute lifecycle: any entity can file a dispute against any trust decision. Human appeal endpoint requires no authentication. |

---

## Article 15 — Accuracy, Robustness, Cybersecurity

| Requirement | EP Implementation |
|-------------|-------------------|
| 15(1): Appropriate level of accuracy | EP provides configurable policy thresholds. Four assurance levels (low/medium/substantial/high). Domain-specific scoring. |
| 15(3): Resilient against errors | EP: 5-mechanism replay prevention, atomic RPCs with FOR UPDATE locks, fail-closed design on all trust-bearing operations. |
| 15(4): Cybersecurity measures | EP: RLS on all 50 tables, timing-safe auth, CSP with per-request nonce, HSTS, write guard, SIEM integration. Formal threat model documented. |

---

## Article 26 — Obligations of Deployers

| Requirement | EP Implementation |
|-------------|-------------------|
| 26(1): Use in accordance with instructions | EP policy engine enforces usage boundaries. Actions outside policy scope are rejected by Handshake verification. |
| 26(5): Impact assessments for high-risk systems | EP Cloud compliance dashboard provides audit-ready exports, trust score histories, and dispute resolution records. |

---

## Summary

| Article | Coverage | Key EP Primitives |
|---------|----------|-------------------|
| Art. 9 (Risk Management) | Full | Eye, Trust Profile, adversarial testing, formal verification |
| Art. 10 (Data Governance) | Full | Provenance tiers, Sybil resistance, write guard |
| Art. 11 (Documentation) | Full | PROTOCOL-STANDARD, PIPs, architecture docs |
| Art. 12 (Record-Keeping) | Full | protocol_events, handshake_events, audit_events, SIEM |
| Art. 13 (Transparency) | Full | Trust Decisions with reasons, commitment proofs |
| Art. 14 (Human Oversight) | Full | Accountable Signoff, delegation judgment, dispute lifecycle |
| Art. 15 (Accuracy/Security) | Full | Replay prevention, RLS, atomic RPCs, CSP |
| Art. 26 (Deployer Obligations) | Full | Policy enforcement, compliance dashboard |
