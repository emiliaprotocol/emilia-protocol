# EMILIA Protocol — Evolution Vision v2

**Supersedes:** EP-SX-EVOLUTION-VISION.docx  
**Date:** April 2026  
**Status:** Strategic roadmap  

---

## The Thesis

AI systems will be required — by law — to prove they had authorization before they acted. When that happens, there will be two options:

1. Every company builds their own proprietary audit system (fragmented, non-interoperable, unverifiable)
2. Everyone adopts an open protocol (interoperable, verifiable, composable, free)

EP bets on option 2. The protocol that wins will be the one that was ready when the world needed it.

---

## Where EP Is Today (April 2026)

### Working Software
- 112,000+ live handshakes processed
- 670+ automated tests, 116 adversarial cases
- 50 database tables, all RLS-hardened, all search_path-pinned
- 45+ API endpoints, all rate-limited, all auth-enforced
- MCP server with 34 tools — native AI agent integration
- TypeScript + Python SDKs
- Base L2 blockchain anchoring (~$0.60/month)

### Formal Verification
- 25 TLA+ safety properties (413,137 states, 0 errors)
- 35 Alloy relational facts (0 counterexamples)
- Both run in CI on every commit

### Compliance
- NIST AI RMF: 38/38 subcategories mapped
- EU AI Act: Articles 9-15, 26 fully mapped
- SOC 2 Type II: audit engagement planned

### Protocol Governance
- PIP process (6 accepted PIPs)
- EP Core v1.0 formally frozen
- Constitution v5 ratified

---

## The Five-Phase Evolution

### Phase 1: Self-Verifying Protocol (Q2 2026)
**Goal:** Make EP receipts verifiable without EP infrastructure

- [x] Ed25519 entity key pairs (lib/receipt-document.js)
- [x] Self-contained receipt documents (EP-RECEIPT-v1 format)
- [x] Standalone verification library (lib/verify.js — zero dependencies)
- [x] EP Core v1.0 freeze (PIP-001)
- [x] PIP process established (PIP-000)
- [ ] `/.well-known/ep-keys.json` endpoint for entity public key discovery
- [ ] Receipt export API (entity exports their receipt bundle)
- [ ] Cross-language verification libraries (Go, Rust, Python)

**Why this matters:** Until receipts are self-verifying, EP is an API product. After, it's a protocol that can't be killed.

### Phase 2: Compliance Certification (Q3 2026)
**Goal:** Make EP adoptable by regulated institutions

- [x] NIST AI RMF mapping (38/38 subcategories)
- [x] EU AI Act mapping (Articles 9-15, 26)
- [ ] SOC 2 Type II audit (Cure53 + Vanta/Drata)
- [ ] FedRAMP mapping
- [ ] PCI DSS v4 mapping (Requirements 6, 7, 8)
- [ ] HIPAA safeguards mapping
- [ ] Compliance dashboard in EP Cloud
- [ ] Audit-ready report generation

**Why this matters:** Institutions don't adopt technology. They adopt compliance-mapped technology.

### Phase 3: Native LLM Integration (Q3-Q4 2026)
**Goal:** Make trust reasoning native to AI models

- [x] LLM function-calling schema (8 functions, OpenAI + Anthropic format)
- [x] MCP server (34 tools, already deployed)
- [ ] EP Eval benchmark (trust-reasoning evaluation for models)
- [ ] Training dataset (anonymized, open-source trust interactions)
- [ ] Model-readable compact receipt format (one-line, context-window-friendly)
- [ ] System prompt integration guide for model providers
- [ ] Partnership with 1+ model provider for native integration

**Why this matters:** If models understand trust as a reasoning primitive (not just an API call), EP becomes the default choice.

### Phase 4: Federation (Q4 2026 - Q1 2027)
**Goal:** Eliminate single point of failure

- [x] Federation specification v1.0 (FEDERATION-SPEC.md)
- [ ] Operator conformance test suite
- [ ] Federation registry (GitHub-based Phase 1)
- [ ] Cross-operator receipt verification reference implementation
- [ ] Trust profile portability (composite profiles from multi-operator receipts)
- [ ] Second independent EP operator running on AWS
- [ ] DNS-based discovery (Phase 3 federation)

**Why this matters:** No government will bet infrastructure on a single-operator system. Federation is not optional — it's required for the mission.

### Phase 5: Institutional Traction (2027)
**Goal:** Prove the thesis with real deployments

- [ ] First US federal agency pilot (NIST engagement in progress)
- [ ] First financial institution deployment
- [ ] First LLM provider native integration
- [ ] "EP Verified" badge program
- [ ] Insurance API (actuarially useful risk summaries)
- [ ] Trust premium calculator (quantified ROI)
- [ ] On-chain federation registry (Base L2 smart contract)
- [ ] AAIF working group acceptance

---

## Strategic Positioning

### The One-Sentence Pitch

**For different audiences:**

| Audience | Pitch |
|----------|-------|
| Senators | "EP ensures AI systems can't act without verified authorization. It's the seatbelt for AI." |
| Bank CTOs | "EP gives you a cryptographically verifiable audit trail for every high-risk action, mapped to your compliance framework." |
| AI researchers | "EP is an open protocol for pre-action trust enforcement — like HTTPS for AI authorization." |
| Developers | "npm install @emilia-protocol/sdk. Five lines. Your AI agent now has verifiable trust." |
| Regulators | "EP implements NIST AI RMF GOVERN/MAP/MEASURE/MANAGE with formal compliance mappings." |

### Competitive Moat

| Property | EP | Competitors |
|----------|-----|------------|
| Self-verifying receipts | Yes (Ed25519 + Merkle) | No (API-dependent) |
| Formal verification | Yes (TLA+ + Alloy in CI) | No |
| Pre-action enforcement | Yes (Handshake ceremony) | Post-hoc scoring only |
| Named human accountability | Yes (Signoff) | No |
| Due process / appeals | Yes (dispute lifecycle) | No |
| Federation spec | Yes (PIP-006) | No |
| Compliance mappings | NIST + EU AI Act | None |
| MCP integration | 34 tools | 0 |
| Blockchain anchoring | Base L2 | None |

### Economic Model (No Token)

```
Open Protocol (free, Apache 2.0)
    │
    ├── EP Cloud (paid managed offering)
    │   ├── Standard tier (observability, alerts)
    │   ├── Enterprise tier (SLA, dedicated infra)
    │   └── Compliance tier (audit reports, dashboards)
    │
    ├── Vertical Packs (pre-built policies)
    │   ├── Government Pack
    │   ├── Financial Pack
    │   └── Agent Governance Pack
    │
    └── Professional Services
        ├── Integration support
        ├── Custom policy development
        └── Compliance consulting
```

Revenue model: Red Hat to Linux. The protocol is free. Operational convenience is paid.

---

## Active Grant & Standards Engagements

| Engagement | Status | Document |
|------------|--------|----------|
| AAIF working group | Proposal submitted (v3) | docs/AAIF-PROPOSAL-v3.md |
| AWS Open Source Fund | Application drafted | docs/AWS-GRANT-APPLICATION.md |
| NIST AI Safety | Engagement plan active | docs/NIST-ENGAGEMENT-PLAN.md |

---

## Key Metrics to Track

| Metric | Current | 6-Month Target | 12-Month Target |
|--------|---------|-----------------|-----------------|
| Live handshakes | 112K | 500K | 2M |
| Federated operators | 1 | 2 | 5 |
| Compliance certifications | 0 | 1 (SOC 2) | 3 |
| LLM provider integrations | 0 (MCP only) | 1 | 3 |
| Government pilots | 0 | 1 | 2 |
| Financial institution deployments | 0 | 0 | 1 |
| Open-source contributors | 1 | 5 | 15 |

---

*This document supersedes EP-SX-EVOLUTION-VISION.docx. The strategic direction has shifted from software trust extension (EP-SX) to full-stack protocol evolution with federation, compliance certification, and native LLM integration.*
