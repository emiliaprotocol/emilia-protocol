# EMILIA Protocol — Proposal for AAIF Standardization

**Version:** 3.0  
**Date:** April 2026  
**Author:** Iman Schrock, Protocol Author & CEO  
**License:** Apache 2.0  
**Repository:** github.com/emilia-protocol  

---

## One Sentence

**EMILIA Protocol is an open standard for verifiable pre-action authorization in AI systems — the proof that an AI asked permission before it acted.**

---

## Why This Matters Now

AI systems are moving from **recommendation to execution**. Models now deploy code, transfer funds, modify infrastructure, and act on behalf of humans. The missing governance layer is not model quality — it is **action control**.

MCP tells agents how to use tools. EMILIA Protocol tells systems **whether a specific high-risk action should be allowed to proceed**.

When the first catastrophic unauthorized AI action makes headlines, every government, financial institution, and enterprise will need the same thing: a verifiable, auditable, tamper-evident record that the action was authorized, by whom, under what policy, and with what evidence. They will need it to be open, interoperable, and not controlled by any single vendor.

That is what EP provides.

---

## What EP Is

### The Protocol Stack

```
EP Eye         OBSERVE → SHADOW → ENFORCE lifecycle
               Classifies risk patterns. Informs policy. Does not decide.

EP Handshake   Pre-action trust ceremony
               Binds identity + authority + policy + action + nonce + expiry
               Consumed exactly once. Replay-resistant.

EP Signoff     Named human accountability
               Specific principal assumes irrevocable ownership of outcome
               Cryptographically bound. One-time consumable.

EP Commit      Atomic action seal
               Immutable. Hash-linked. Blockchain-anchored.
               No partial states. Sealed on write.
```

### Core Objects (EP Core v1.0 — Frozen)

| Object | Purpose | Interoperability Role |
|--------|---------|----------------------|
| **Trust Receipt** | Portable, signed record of trust-relevant interaction | The atomic unit. Self-contained, Ed25519-signed, Merkle-anchored. Verifiable without EP infrastructure. |
| **Trust Profile** | Structured trust state derived from receipts | Read-only projection. Score, confidence, evidence depth, domain breakdown. |
| **Trust Decision** | Policy-evaluated result for a specific action | `allow`/`review`/`deny` with reasons, evidence, and appeal path. |

### What Makes EP Different From Every Other Trust Proposal

1. **Self-verifying receipts.** An EP receipt is a self-contained, Ed25519-signed, Merkle-anchored document. Anyone can verify it without calling EP's API, without an account, without any trust relationship with the operator. Like Bitcoin transactions — just math.

2. **Pre-action enforcement, not post-hoc scoring.** EP doesn't rate entities after the fact. It gates actions before they execute. No verified Handshake = no action.

3. **Named human accountability.** When an AI acts with real-world consequences, EP's Signoff layer ensures a specific named human has seen the exact action, understood the consequences, and accepted responsibility. Not a role. A person.

4. **Formal verification.** 26 TLA+ safety properties verified by model checking (T1–T26, 413,137 states, 0 errors) — including the EP-IX identity continuity invariants. 35 Alloy relational facts + 15 assertions verified (Alloy 6.0.0, 0 counterexamples). Both run in CI on every commit.

5. **Due process.** Disputes, appeals, human reports, graph-based adjudication. Trust must never be more powerful than appeal.

6. **Federation-ready.** EP is designed for multiple independent operators that cross-verify via cryptographic proofs — not a single central authority.

---

## Technical Maturity

EP is not a proposal. It is production-grade software with formal verification.

| Metric | Value |
|--------|-------|
| **Automated tests** | 3,483 across 132 files (vitest) |
| **Adversarial tests** | 85 red team cases (`docs/conformance/RED_TEAM_CASES.md`) |
| **Property-based tests** | Fast-check invariant tests |
| **Mutation testing** | Stryker.js, 80%+ kill threshold |
| **Formal verification** | TLA+: 26 properties verified (T1–T26, 413,137 states, 0 errors). Alloy: 35 facts, 15 assertions verified (Alloy 6.0.0, 0 counterexamples) |
| **Database tables** | ~50 (all RLS-enabled with explicit policies) |
| **SECURITY DEFINER functions** | 27 (all search_path-hardened) |
| **API endpoints** | 50+ routes, all rate-limited |
| **MCP tools** | 34 (trust profile, handshake, receipt, signoff, commit, dispute, delegation) |
| **SDKs** | TypeScript (`sdks/typescript/`) + Python (`sdks/python/`) |
| **Blockchain anchoring** | Base L2, Merkle root publishing |
| **Performance** | Handshake create p95: 575ms at 50 VUs (per `docs/operations/PERFORMANCE_PROOF.md`) |
| **Conformance** | 7/7 required checks PASS — `CONFORMANT: EP Core v1.0` |
| **CI quality gates** | ~13 workflows in `.github/workflows/` (incl. Playwright E2E) |
| **Standalone verify** | `npm install @emilia-protocol/verify` — zero deps, Apache-2.0, published on npm |
| **Adoption primitives** | Trust Explorer, Playground, Adopt page (all shipped) |
| **AWS deployment** | CloudFormation template at `infrastructure/aws/template.yaml` |
| **Pre-execution products** | EP GovGuard + EP FinGuard v1 trust-receipts API |
| **Security audit** | Internal audit score 100/100 (self-administered, see `docs/security/AUDIT_METHODOLOGY.md`); third-party engagement planned |

---

## Compliance Readiness

EP has formal compliance mappings for:

| Framework | Coverage |
|-----------|----------|
| **NIST AI RMF 1.0** | 38 subcategories mapped across GOVERN, MAP, MEASURE, MANAGE — see `docs/compliance/NIST-AI-RMF-MAPPING.md`. (NIST AI RMF 1.0 has additional subcategories beyond these 38; the mapping is high-risk-AI-systems-focused, not exhaustive across the full framework.) |
| **EU AI Act** | Articles 9–15 and 26 mapped — high-risk AI systems (Title III, Chapter 2). See `docs/compliance/EU-AI-ACT-MAPPING.md`. |
| **SOC 2 Type II** | Preparation underway; auditor selection in progress. |

These are not aspirational — they cite specific EP primitives, API endpoints, and architectural features for each requirement.

---

## Protocol Governance

EP uses a **Protocol Improvement Proposal (PIP)** process modeled on Bitcoin's BIPs:

| PIP | Title | Status |
|-----|-------|--------|
| PIP-000 | PIP Process | Active |
| PIP-001 | EP Core v1.0 Freeze | Accepted |
| PIP-002 | Handshake Extension | Accepted |
| PIP-003 | Accountable Signoff Extension | Accepted |
| PIP-004 | EP Commit Extension | Accepted |
| PIP-005 | Emilia Eye Extension | Accepted |
| PIP-006 | Federation Specification | Draft |

**Core freeze rule:** EP Core v1.0 objects are frozen. Changes require a Core-type PIP, 90-day review, consensus, major version bump, and 24-month deprecation window. Extensions can be added at any time without modifying Core.

---

## What EP Proposes to AAIF

### 1. Adopt EP Core as a minimal interoperable trust interface

Three objects — Trust Receipt, Trust Profile, Trust Decision — as the standard interface for trust evaluation in AI agent systems. Any system that implements these three objects can interoperate with any other conformant system.

### 2. Standardize the EP function-calling schema for LLMs

Eight function definitions (3 core + 5 extended) that any model provider can implement to make their models trust-aware:
- `ep_check_trust` — Should I trust this entity for this action?
- `ep_record_interaction` — Record what happened
- `ep_request_authorization` — Get pre-action authorization
- `ep_verify_receipt` — Verify a receipt offline
- `ep_prove_trust` — Privacy-preserving trust proof
- `ep_get_trust_profile` — Read trust state
- `ep_file_dispute` — Contest a decision
- `ep_human_signoff` — Request human accountability

### 3. Recognize self-verifying receipts as the trust primitive for AI

EP-RECEIPT-v1 documents are self-contained, signed, and anchor-provable. They don't require a central authority to verify. This is the property that makes EP a protocol rather than a product — and the property that makes it suitable for standardization.

### 4. Evaluate the federation model for multi-operator trust

EP's federation specification enables multiple independent operators to issue and cross-verify receipts. This eliminates single-point-of-failure and enables sector-specific operators (government, financial, healthcare) that interoperate through shared cryptographic proofs.

---

## Federation Vision: How EP Scales

```
Government Operator          Financial Operator          AI Platform Operator
(US Treasury / GSA)          (JPMorgan / Fed)            (Anthropic / OpenAI)
       │                            │                            │
       ├── Issues receipts          ├── Issues receipts          ├── Issues receipts
       ├── Anchors to Base L2       ├── Anchors to Base L2       ├── Anchors to Base L2  
       ├── /.well-known/ep-*        ├── /.well-known/ep-*        ├── /.well-known/ep-*
       │                            │                            │
       └────────────── Cross-verify via Ed25519 + Merkle proofs ─┘
                           No trust between operators needed
                           Just math
```

---

## What EP Is NOT

- **Not a token.** No cryptocurrency, no DeFi, no trading. Just math.
- **Not a reputation system.** EP doesn't produce public scores or persistent labels. It evaluates trust decisions in context.
- **Not a model.** EP is infrastructure. It works with any model from any provider.
- **Not a product.** EP is an open protocol. EP Cloud is the commercial managed offering, like Red Hat to Linux.

---

## Open Source

- **License:** Apache 2.0
- **Repository:** All source, formal models, test suites, and CI workflows are public
- **DCO enforcement:** On every PR
- **SBOM + provenance:** Attestation on every release

---

## Ask

AAIF should evaluate EP against this question:

> When an AI system takes a consequential action, what is the open, interoperable, verifiable standard for proving that the action was authorized?

EP answers that question with working software, formal verification, compliance mappings, and a governance model designed for multi-stakeholder adoption.

We request:
1. Working group consideration for EP Core as an interoperable trust interface
2. Feedback on the federation specification from member organizations
3. Pilot coordination with AAIF members operating in regulated environments

---

## Contact

Iman Schrock  
Protocol Author & CEO  
iman@emiliaprotocol.ai  
github.com/emilia-protocol
