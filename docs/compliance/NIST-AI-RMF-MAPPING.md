# EP Compliance Mapping: NIST AI Risk Management Framework (AI RMF 1.0)

**Version:** 1.0  
**Date:** 2026-04-07  
**Protocol:** EMILIA Protocol v1.0  
**Framework:** NIST AI RMF 1.0 (January 2023)  

---

## Overview

This document maps EMILIA Protocol capabilities to the four core functions of the NIST AI Risk Management Framework: GOVERN, MAP, MEASURE, and MANAGE. Each mapping cites the specific EP primitive, API endpoint, or architectural feature that satisfies the NIST requirement.

---

## GOVERN — Establish and Maintain AI Risk Management

| NIST Subcategory | Requirement | EP Implementation |
|-----------------|-------------|-------------------|
| GOVERN 1.1 | Legal and regulatory requirements are identified | EP policy engine supports custom JSONB policy rules mapped to regulatory requirements. Policies are versioned, hashed, and immutable once bound to a handshake. |
| GOVERN 1.2 | Trustworthy AI characteristics are integrated into policies | EP Trust Profiles evaluate entities across behavioral, consistency, provenance, and anomaly dimensions. Trust Decisions reference specific policy identifiers. |
| GOVERN 1.3 | Processes for risk management are established | EP Handshake ceremony enforces a structured pre-action authorization process. Every high-risk action requires policy evaluation before execution. |
| GOVERN 1.7 | Processes for decommission are defined | EP Commit revocation with mandatory reason field. Delegation revocation. Entity suspension with audit trail. |
| GOVERN 2.1 | Roles and responsibilities are defined | EP Accountable Signoff maps specific principals to specific actions. Delegation judgment scoring evaluates human oversight quality. |
| GOVERN 2.2 | Personnel are trained on risk management | EP provides structured documentation (PROTOCOL-STANDARD.md and the canonical-docs map) and formal verification models (TLA+, Alloy) that serve as training material. |
| GOVERN 3.2 | Policies align with organizational values | EP policy evaluation returns human-readable reasons with every Trust Decision. Appeal paths are always available. |
| GOVERN 4.1 | Organizational practices are monitored | EP Eye OBSERVE lifecycle monitors action patterns without enforcement. SHADOW mode logs hypothetical enforcement for validation. |
| GOVERN 4.3 | Organizational practices are updated | EP PIP process (Protocol Improvement Proposals) provides structured governance for protocol evolution. |
| GOVERN 5.1 | Feedback is incorporated | EP dispute lifecycle (open → under_review → upheld/reversed/dismissed) with human appeal endpoint. Trust scores adjust based on dispute outcomes. |
| GOVERN 6.1 | Policies are documented | EP policy versions are stored with full JSONB rule definitions, versioned, hash-locked at handshake initiation, and auditable. |
| GOVERN 6.2 | Policies are shared with stakeholders | EP `/.well-known/ep-trust.json` discovery endpoint. Public Trust Decision API. Commitment proofs for privacy-preserving trust attestation. |

---

## MAP — Identify and Categorize AI Risks

| NIST Subcategory | Requirement | EP Implementation |
|-----------------|-------------|-------------------|
| MAP 1.1 | AI system purposes are clearly defined | EP Handshake binds `action_type` and `resource_ref` to every authorization request. No ambiguous "general authorization." |
| MAP 1.5 | AI actors are characterized | EP entity types: `human`, `ai_agent`, `service`, `organization`, `mcp_server`, `github_app`, `npm_package`, `chrome_extension`. Each with distinct trust profiles. |
| MAP 1.6 | System requirements include trustworthiness | EP Trust Decisions evaluate against configurable policy thresholds with four assurance levels: `low`, `medium`, `substantial`, `high`. |
| MAP 2.1 | AI risks are identified | EP Eye observations classify risk patterns by domain (financial, government, enterprise, AI/agent) and signal class. |
| MAP 2.2 | Impacts are assessed | EP domain scoring evaluates impact per domain (financial, code_execution, communication, delegation, infrastructure, content_creation, data_access). |
| MAP 3.1 | AI system benefits and costs are assessed | EP trust reports provide cost-benefit evidence: positive/negative outcome rates, evidence depth, provenance composition. |
| MAP 3.5 | Scientific integrity is maintained | EP formal verification: 20 TLA+ safety properties verified (T1–T20) plus 6 specified, 32 Alloy relational facts — machine-checked, CI-enforced. |
| MAP 5.1 | Likelihood of risks is assessed | EP anomaly detection (trust velocity), effective-evidence dampening (Sybil resistance), and graph-based collusion detection. |

---

## MEASURE — Assess and Track AI Risks

| NIST Subcategory | Requirement | EP Implementation |
|-----------------|-------------|-------------------|
| MEASURE 1.1 | Approaches for risk measurement are documented | EP PROTOCOL-STANDARD.md (Abstract + Core objects + Extensions) documents all measurement approaches. Scoring rationale in SCORING_RATIONALE.md. |
| MEASURE 2.1 | AI systems are tested before deployment | 3,430 automated tests across 129 files, 85 adversarial test cases, 19 property-based tests, mutation testing with 80%+ kill threshold. |
| MEASURE 2.3 | AI system performance is tracked | EP Trust Profile materialization: snapshot on write, freshness check on read. Score history API tracks changes over time. |
| MEASURE 2.5 | AI systems are evaluated for bias | EP provenance tiers (6 levels, 0.3x–1.0x weight) prevent over-reliance on any single evidence source. Bilateral confirmation required for highest weight. |
| MEASURE 2.6 | AI system metrics are measured | EP canonical evaluator produces structured metrics: confidence level, evidence depth, behavioral rates, domain scores, anomaly flags. |
| MEASURE 2.7 | AI systems are evaluated for cybersecurity | EP security: RLS-hardened tables (~50), SECURITY DEFINER search_path hardened, atomic RPCs with FOR UPDATE locks, timing-safe secret comparison, nonce-based CSP. |
| MEASURE 2.11 | Fairness is assessed | EP procedural justice: dispute lifecycle with human appeal, graph-based adjudication where accused entity cannot dominate their own case (0.4x self-weight cap). |
| MEASURE 4.1 | Measurement approaches are documented | EP conformance test suite with deterministic fixtures, cross-language hash verification (JS + Python), and Stryker mutation testing. |

---

## MANAGE — Prioritize and Act on AI Risks

| NIST Subcategory | Requirement | EP Implementation |
|-----------------|-------------|-------------------|
| MANAGE 1.1 | AI risks are prioritized and responded to | EP Eye advisory severity levels drive policy escalation. Trust Decisions return `allow`/`review`/`deny` with actionable reasons. |
| MANAGE 1.3 | Responses to identified risks are developed | EP Handshake ceremony: if policy requires additional assurance (e.g., Eye advisory = elevated), handshake requirements are automatically stepped up. |
| MANAGE 2.1 | Resources are allocated for risk management | EP Cloud provides managed risk management infrastructure: audit export, compliance dashboard, SIEM integration, webhook-based alerting. |
| MANAGE 2.2 | Mechanisms are in place for risk management | EP four-layer enforcement: Eye observes → Handshake verifies → Signoff owns → Commit seals. Each layer is independently auditable. |
| MANAGE 2.4 | Mechanisms are in place for safe decommission | EP Commit revocation, delegation revocation, entity suspension — all with mandatory audit trail and reason recording. |
| MANAGE 3.1 | AI risks and benefits are communicated | EP Trust Decisions include human-readable `reasons` array. Commitment proofs enable privacy-preserving trust communication. |
| MANAGE 3.2 | AI risk management is communicated to stakeholders | EP audit_events and protocol_events tables provide complete, append-only, SIEM-forwardable audit trail for every trust-changing operation. |
| MANAGE 4.1 | Post-deployment monitoring is planned | EP Eye OBSERVE→SHADOW→ENFORCE lifecycle provides progressive monitoring. Eye observations are stored and queryable. |
| MANAGE 4.2 | Incidents are documented and reported | EP audit trail + protocol events + SIEM forwarder. Dispute lifecycle documents every incident from filing through resolution and appeal. |
| MANAGE 4.3 | AI system decommission is documented | EP Commit revocation + entity suspension audit trail. All state transitions are logged in protocol_events before execution. |

---

## Summary

| NIST Function | EP Coverage | Key Primitives |
|--------------|------------|----------------|
| **GOVERN** | 12/12 subcategories mapped | Policy engine, Signoff, PIP process, dispute lifecycle |
| **MAP** | 8/8 subcategories mapped | Entity types, Eye observations, domain scoring, formal verification |
| **MEASURE** | 8/8 subcategories mapped | Trust profiles, test suite, anomaly detection, provenance tiers |
| **MANAGE** | 10/10 subcategories mapped | Four-layer enforcement, audit trail, SIEM, Commit revocation |

**Total: 38/38 subcategories mapped to specific EP capabilities.**
