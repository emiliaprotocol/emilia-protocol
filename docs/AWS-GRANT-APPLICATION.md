# AWS Open Source Grant Application — EMILIA Protocol

**Program:** AWS Open Source Fund / AWS AI & ML Research Grants  
**Date:** April 2026  
**Applicant:** Iman Schrock, Protocol Author & CEO  
**Project:** EMILIA Protocol (EP)  
**License:** Apache 2.0  
**Repository:** github.com/emilia-protocol  

---

## Project Title

**EMILIA Protocol: An Open Standard for Verifiable Pre-Action Authorization in AI Systems**

---

## Executive Summary

EMILIA Protocol (EP) is an open-source trust enforcement protocol for AI agent systems. It provides cryptographically verifiable, policy-bound, pre-action authorization — ensuring that every consequential AI action has a tamper-evident record of who authorized it, under what policy, and with what evidence.

EP is the missing governance layer between model capability and action execution. As AI systems move from recommendation to autonomous execution across government, financial, and enterprise workflows, the need for a standardized, verifiable authorization protocol becomes critical.

We seek AWS funding to:
1. Build a **standalone verification library** enabling offline, infrastructure-free receipt verification
2. Develop **federation infrastructure** allowing multiple independent operators to cross-verify trust evidence
3. Complete **compliance certification** (SOC 2 Type II) and formal compliance mappings (NIST AI RMF, EU AI Act)
4. Create an **LLM trust evaluation benchmark** (EP Eval) for measuring model trust-reasoning capability

---

## Problem Statement

AI agents are now executing consequential real-world actions: deploying code, transferring funds, modifying infrastructure, making medical recommendations, and acting in government workflows. The governance question is no longer "is this model accurate?" but **"did this AI have authorization to take this action?"**

Current approaches fail because:
- **Proprietary audit systems** are fragmented, non-interoperable, and unverifiable by third parties
- **Reputation systems** produce opaque scores without cryptographic verifiability
- **Access control systems** (RBAC, ABAC) weren't designed for AI-agent-to-AI-agent trust decisions
- **No existing protocol** provides self-verifying, portable, privacy-preserving trust evidence

The risk is real and immediate: without a standardized authorization protocol, the first catastrophic unauthorized AI action will trigger fragmented, incompatible regulatory responses that harm the entire AI ecosystem.

---

## Solution: EMILIA Protocol

EP provides four composable layers:

| Layer | Function | Innovation |
|-------|----------|------------|
| **Eye** | Observes risk patterns (OBSERVE→SHADOW→ENFORCE) | Graduated enforcement without binary on/off |
| **Handshake** | Pre-action authorization ceremony | 7-property cryptographic binding, replay-resistant, one-time consumption |
| **Signoff** | Named human accountability | Specific principal (not role) assumes irrevocable ownership of outcome |
| **Commit** | Atomic action seal | Immutable, hash-linked, blockchain-anchored. No partial states. |

### Key Technical Innovations

1. **Self-verifying trust receipts:** EP-RECEIPT-v1 documents are Ed25519-signed, Merkle-anchored, and verifiable without any EP infrastructure — like Bitcoin transactions.

2. **Privacy-preserving trust proofs:** Entities can prove "my trust score exceeds threshold X in domain Y" without revealing their receipts, counterparties, or interaction history (HMAC-SHA256 commitment scheme).

3. **Formal verification:** 25 TLA+ safety properties and 32 Alloy relational facts, machine-checked and CI-enforced. This is production protocol assurance, not academic exercise.

4. **Federation architecture:** Multiple independent operators issue and cross-verify receipts via shared cryptographic proofs. No single point of failure. No central authority.

---

## Current State (Production-Ready)

| Metric | Value |
|--------|-------|
| Live handshakes processed | 112,000+ |
| Automated tests | 3,235 across 124 files |
| Adversarial/red-team tests | 116 cases |
| Formal verification | TLA+ (7,857 states) + Alloy (32 facts, 15 assertions) |
| Database tables | 50 (all RLS-hardened) |
| API endpoints | 45+ (all rate-limited, auth-enforced) |
| MCP tools | 34 (native AI agent integration) |
| SDKs | TypeScript + Python |
| Blockchain anchoring | Base L2, Merkle roots, ~$0.60/month |
| Compliance mappings | NIST AI RMF (38/38 subcategories), EU AI Act (Articles 9-15, 26) |
| Protocol governance | PIP process (6 accepted PIPs) |

---

## Funding Request

**Total requested:** $150,000 over 12 months

### Budget Breakdown

| Item | Amount | Purpose |
|------|--------|---------|
| **Standalone verification library** | $25,000 | Zero-dependency offline receipt verification. JS library (`@emilia-protocol/verify`) is **shipped** — funding covers Python/Go/Rust ports + npm publication + auditing. |
| **Federation infrastructure** | $40,000 | Conformance test **passes 7/7** on primary operator. Funding covers: AWS CloudFormation deployment of second operator (template exists at `infrastructure/aws/template.yaml`), federation registry, cross-operator verification. |
| **SOC 2 Type II certification** | $30,000 | Third-party audit (Cure53 or equivalent) + Vanta/Drata continuous compliance monitoring. Required for enterprise and government adoption. |
| **EP Eval benchmark** | $20,000 | Open-source benchmark for measuring LLM trust-reasoning capability. Training datasets (anonymized). Integration test suite for model providers. |
| **Infrastructure** | $15,000 | AWS hosting for federation registry, CI/CD, staging environments for multi-operator testing. |
| **Community & documentation** | $10,000 | Contributor onboarding, compliance mapping PDFs, one-pager documents for procurement teams. |
| **Security audit** | $10,000 | Targeted penetration test of handshake ceremony, commitment proof API, and federation cross-verification. |

---

## Impact & Outcomes

### 12-Month Deliverables

| Deliverable | Timeline | Measurable Outcome |
|-------------|----------|-------------------|
| Standalone verification library (cross-language) | Month 1-3 | JS library shipped (`packages/verify/`). Python/Go/Rust ports + npm publish + third-party audit of crypto implementation |
| EP Core v1.0 formal specification | Month 1-2 | Published RFC-style document suitable for standards body review |
| SOC 2 Type II report | Month 3-6 | Audit report that enterprise procurement teams can evaluate |
| Federation reference implementation | Month 4-8 | Deploy second operator on AWS using existing CloudFormation template (`infrastructure/aws/template.yaml`), run conformance test, demonstrate cross-operator receipt verification |
| EP Eval benchmark | Month 6-9 | Open-source benchmark available on GitHub, evaluated against 3+ model providers |
| NIST/EU compliance mapping (formal PDFs) | Month 2-4 | Published documents mapping EP to NIST AI RMF and EU AI Act requirements |
| First government pilot | Month 9-12 | Working pilot with a US federal agency (NIST engagement in progress) |

### Long-Term Impact

1. **Open standard adoption:** EP Core becomes the default trust interface for AI agent systems, similar to how TLS became the default for web security.
2. **Regulatory alignment:** Compliance mappings enable EP to serve as the implementation layer for NIST AI RMF, EU AI Act, and future regulations.
3. **Multi-stakeholder governance:** PIP process enables community-driven protocol evolution without destabilizing the frozen core.
4. **Economic ecosystem:** EP Cloud (commercial managed offering) sustains protocol development while the core protocol remains free and open.

---

## Why AWS

1. **Infrastructure scale:** EP federation requires globally distributed infrastructure for multi-operator testing. AWS provides the geographic distribution and reliability needed.
2. **AI ecosystem alignment:** AWS Bedrock, SageMaker, and the broader AWS AI/ML stack are prime integration targets for EP's trust enforcement. Models running on AWS should have native trust primitives.
3. **Government cloud:** AWS GovCloud is the primary infrastructure for US federal AI deployments. EP's government pilot work aligns directly with AWS's government cloud strategy.
4. **Open source commitment:** AWS's track record with open-source projects (OpenSearch, Bottlerocket, Cedar) demonstrates alignment with EP's Apache 2.0 licensing and community governance model.

---

## Team

**Iman Schrock** — Protocol Author & CEO
- Designed and implemented the full EP protocol stack
- Background in trust systems, cryptographic protocols, and regulated-industry software
- Active engagement with NIST AI safety working groups and AAIF

---

## Open Source Commitment

- **License:** Apache 2.0 (irrevocable)
- **All deliverables:** Published on GitHub under the same license
- **DCO enforcement:** On every contribution
- **SBOM + provenance:** Attestation on every release
- **No open-core bait-and-switch:** The protocol is fully open. EP Cloud is the managed offering, not a gated feature set.

---

## References

- **GitHub:** github.com/emilia-protocol
- **Protocol Standard:** PROTOCOL-STANDARD.md (17 sections)
- **Formal Models:** formal/ep_handshake.tla, formal/ep_relations.als
- **NIST Engagement:** docs/NIST-ENGAGEMENT-PLAN.md
- **AAIF Proposal:** docs/AAIF-PROPOSAL-v3.md
- **Compliance Mappings:** docs/compliance/NIST-AI-RMF-MAPPING.md, docs/compliance/EU-AI-ACT-MAPPING.md
- **Federation Spec:** docs/FEDERATION-SPEC.md
- **LLM Schema:** docs/LLM-FUNCTION-CALLING-SCHEMA.md
- **Vision:** docs/VISION-BITCOIN-OF-TRUST.md

---

## Contact

Iman Schrock  
iman@emiliaprotocol.ai  
github.com/emilia-protocol
