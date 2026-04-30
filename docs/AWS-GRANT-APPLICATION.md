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

3. **Formal verification:** 20 TLA+ safety properties verified (T1–T20, TLC 2.19, 7,857 states, 0 errors); 6 additional EP-IX properties (T21–T26) specified, model run pending. 32 Alloy relational facts + 15 assertions verified. All run in CI.

4. **Federation architecture:** Multiple independent operators issue and cross-verify receipts via shared cryptographic proofs. No single point of failure. No central authority.

---

## Productized Surfaces: EP GovGuard + EP FinGuard

EMILIA Protocol is the open standard. EP GovGuard and EP FinGuard are the
productized surfaces — the same v1 trust-receipts API pre-filled for two
high-leverage pilot domains:

- **EP GovGuard** ([/govguard](https://emiliaprotocol.ai/govguard)) — pre-execution control for government benefit/payment changes.
  Domain adapters: benefit-bank-account changes, caseworker overrides.
- **EP FinGuard** ([/finguard](https://emiliaprotocol.ai/finguard)) — pre-execution trust for treasury & payment ops.
  Domain adapters: vendor-bank-change, beneficiary creation, large payment release, AI-agent-initiated payment actions.

Both share a single API surface:

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/trust-receipts` | Create receipt (precheck + policy eval + audit emit) |
| `GET /api/v1/trust-receipts/{id}` | Read receipt state (replays event log) |
| `POST /api/v1/trust-receipts/{id}/consume` | One-time consume bound to action_hash |
| `GET /api/v1/trust-receipts/{id}/evidence` | Full evidence packet (timeline, signoff trail, consume record) |
| `POST /api/v1/signoffs/request` | Open a signoff request against a pending receipt |
| `POST /api/v1/signoffs/{id}/approve` | Approver acts (self-approval forbidden, action_hash bound) |
| `POST /api/v1/signoffs/{id}/reject` | Approver rejects |

Three enforcement modes (per-organization, per-action-type): **observe** (log
only, never block — the audit-only rollout posture), **warn** (return decision,
let caller decide), **enforce** (fail closed). Pilots typically start in observe
for 2–4 weeks to generate the "what would have been blocked" report, then
flip to enforce once the agency or institution is comfortable with the
delta.

---

## Current State (Production-Ready)

| Metric | Value |
|--------|-------|
| Automated tests | 3,430 across 129 files (vitest) |
| Adversarial / red-team test cases | 85 cataloged in `docs/conformance/RED_TEAM_CASES.md` |
| Formal verification | TLA+: 20 properties verified (T1–T20, TLC 2.19, 7,857 states, 0 errors); 6 EP-IX properties (T21–T26) specified, model run pending. Alloy: 32 facts, 15 assertions (Alloy 6.1.0). |
| Database tables | ~50, all RLS-hardened (see `supabase/migrations/`) |
| API endpoints | 50+ (all rate-limited; mutating endpoints auth-enforced via `middleware.js` ROUTE_POLICIES) |
| MCP tools | 34 EP-prefixed tools (`mcp-server/index.js`) |
| SDKs | TypeScript SDK in repo (`sdks/typescript/`); Python SDK in repo (`sdks/python/`); npm-published `@emilia-protocol/sdk@0.1.0` |
| Blockchain anchoring | Base L2, Merkle roots (`lib/blockchain.js`) |
| Compliance mappings | 38 NIST AI RMF subcategories mapped across all four functions (GOVERN, MAP, MEASURE, MANAGE); EU AI Act Articles 9–15 + 26 (Title III, Chapter 2 — high-risk AI systems) |
| Protocol governance | PIP process — 5 PIPs accepted (PIP-001 through PIP-005). PIP-006 Federation in design. |
| Pre-execution product surface | EP GovGuard + EP FinGuard v1 trust-receipts API (`/api/v1/trust-receipts/*`, `/api/v1/signoffs/*`) |

---

## Funding Request

**Total requested:** $150,000 over 12 months

### Budget Breakdown

| Item | Amount | Purpose |
|------|--------|---------|
| **Standalone verification library** | $25,000 | Zero-dependency offline receipt verification. JS library (`@emilia-protocol/verify`) is **shipped and published** ([npmjs.com](https://www.npmjs.com/package/@emilia-protocol/verify)) — funding covers Python/Go/Rust ports + third-party audit of the crypto implementation. |
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
| Standalone verification library (cross-language) | Month 1-3 | JS library published on npm (`@emilia-protocol/verify@1.0.1`, current `latest`; 1.0.0 deprecated for shallow-canonicalization regression). Python/Go/Rust ports + third-party audit of the crypto implementation. |
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
- **Protocol Standard:** PROTOCOL-STANDARD.md (Abstract + Core objects + Extensions)
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
