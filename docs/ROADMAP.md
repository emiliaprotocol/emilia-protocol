# EP Master Roadmap

**Updated:** March 2026
**Mission:** Portable trust for machine counterparties and third-party software.

---

## What's Built (Shipped)

### Trust Engine
- [x] Behavioral-first v2 weights (behavioral 40%, consistency 25%)
- [x] Four-factor receipt weighting: submitter × time × graph × provenance
- [x] Effective-evidence dampening (Sybil resistance)
- [x] Trust profiles as canonical output
- [x] Policy evaluation (strict/standard/permissive/discovery + custom JSONB)
- [x] Context-aware evaluation with global fallback
- [x] Current vs historical confidence separation
- [x] Anomaly detection (score velocity)
- [x] Provenance tiers (6 levels, 0.3x–1.0x weight)
- [x] Bilateral attestations (confirm/dispute, 48h window)

### Receipt System
- [x] Canonical receipt pipeline (createReceipt())
- [x] SHA-256 chain-linked hashing with canonical JSON
- [x] Context keys (task_type, category, geo, modality, value_band, risk_class)
- [x] DB immutability triggers
- [x] transaction_ref mandatory
- [x] Provenance tier on every receipt
- [x] Bilateral confirmation endpoint

### Sybil Resistance
- [x] Identity-aware rate limiting (API key + IP on writes)
- [x] Graph analysis (closed-loop 0.4x, thin-graph 0.5x, cluster 0.1x)
- [x] Submitter credibility (unestablished = 0.1x)
- [x] Effective-evidence dampening
- [x] Server-derived owner_id

### Due Process
- [x] Dispute lifecycle (open → under_review → upheld/reversed/dismissed)
- [x] Human appeal (POST /api/disputes/report, no auth required)
- [x] Evidence redaction in public views
- [x] Score recomputation on reversal
- [x] Dispute rate limiting (5/hour disputes, 3/hour reports)
- [x] Human UX page (/appeal)

### Discovery & Routing
- [x] Trust profile endpoint (canonical)
- [x] Policy evaluation endpoint (context-aware)
- [x] Confidence-aware search (rank_by: score/confidence/evidence)
- [x] Confidence-aware leaderboard
- [x] Policy-native needs (JSONB trust policies)
- [x] Context-aware need claim evaluation
- [x] Policy-aware broadcast suggestions
- [x] Context-native feed filtering
- [x] Well-known discovery file (/.well-known/ep-trust.json)

### Distribution
- [x] MCP server (11 tools, context-aware, dispute tools)
- [x] TypeScript + Python SDKs
- [x] Conformance suite (JS + Python, canonical fixtures)
- [x] ~100 tests across 4 files

### Governance & Docs
- [x] EP Core RFC v1.1
- [x] GOVERNANCE.md
- [x] CONTRIBUTING.md
- [x] AAIF working group proposal
- [x] ACP trust extension
- [x] NIST engagement plan
- [x] DTC Shopify integration spec
- [x] EP Constitution v4 Architecture
- [x] EP-SX Software Trust Extension RFC

---

## Phase 1: Ship & Prove (Next 2 Weeks)

### Adoption Actions (Human, not code)
- [ ] Send AAIF email to pr@aaif.org
- [ ] Submit NIST concept paper (April 2 deadline)
- [ ] Send 1 design partner email (Shopify DTC merchant)
- [ ] Send 1 agent framework email (LangChain/CrewAI)
- [ ] Attend MCP Dev Summit NYC (April 2-3)
- [ ] Set up Upstash Redis (production rate limiting)
- [ ] Run all DB migrations (008-014) in Supabase
- [ ] Clean test entities from Supabase
- [ ] Wire RexRuby to submit real receipts after bookings

### Operational
- [ ] Run `npx vitest run` — confirm all tests green
- [ ] Run `python3 conformance/verify_hashes.py` — confirm cross-language
- [ ] Visually verify landing page renders correctly after all changes
- [ ] Fix Cloudflare redirect stripping auth headers on POST
- [ ] Add spec.emiliaprotocol.ai CNAME to Vercel

---

## Phase 2: Production Hardening (Weeks 3-6)

### First Real Data
- [ ] First real receipt from RexRuby booking
- [ ] 50+ real receipts with context keys
- [ ] Measure: did EP-scored routing reduce booking failures?
- [ ] First external entity (not Rex, not Ruby) submitting receipts

### DTC Shopify Integration
- [ ] Build Shopify app (webhook subscription)
- [ ] Normalize events into merchant transaction ledger
- [ ] Emit EP receipts from order lifecycle
- [ ] First DTC merchant with live trust profile

### Testing
- [ ] Route-level integration tests (trust/evaluate, trust/profile, receipts/submit)
- [ ] Dispute flow integration tests
- [ ] Malformed payload / fuzz tests
- [ ] Load testing on evaluate + search endpoints
- [ ] CI pipeline (GitHub Actions) running full suite

---

## Phase 3: Software Trust Extension (Months 2-4)

### EP-SX Core
- [ ] Add software entity types to registration (github_app, npm_package, mcp_server, chrome_extension)
- [ ] Add software receipt types (install_granted, execution_succeeded, incident_opened, etc.)
- [ ] Add permission risk dimension to trust profiles
- [ ] Add publisher trust dimension
- [ ] Install preflight evaluation endpoint
- [ ] Software-specific policy templates (github_private_repo_safe, npm_buildtime_safe, mcp_server_safe)

### Host Adapters
- [ ] GitHub App metadata adapter (permissions, scope, publisher verification)
- [ ] npm provenance adapter (trusted publishing, signatures)
- [ ] MCP registry adapter (server cards, capability declarations)
- [ ] Chrome extension adapter (manifest permissions, store review status)

### Software Discovery
- [ ] EP-SX well-known discovery extension
- [ ] MCP Server Card integration
- [ ] GitHub Marketplace integration spec

---

## Phase 4: Institutional Maturity (Months 4-8)

### Relationship Trust
- [ ] Pairwise trust (A→B in context C)
- [ ] Hierarchical fallback (exact context → nearby → global)
- [ ] Relationship trust endpoint

### Advanced Due Process
- [ ] Community adjudication (reputation-weighted reviewers)
- [ ] Automated escalation rules
- [ ] Dispute SLA monitoring
- [ ] Appeal lifecycle (dispute → appeal → final resolution)

### Governance
- [ ] First external implementation passes conformance suite
- [ ] AAIF working group established
- [ ] Spec v2.0 (formal object model: Attestation vs Evidence vs Trust State vs Policy Result)
- [ ] Conformance certification program
- [ ] Independent security audit

### Advanced Scoring
- [ ] Oracle adapters (DeliveryOracle, PaymentOracle)
- [ ] Provenance-weighted scoring in SQL
- [ ] Cross-ecosystem trust portability

---

## Phase 5: Ecosystem Scale (Months 8-12+)

### Independent Implementations
- [ ] Python reference implementation
- [ ] Go reference implementation
- [ ] At least 2 independent implementations pass conformance
- [ ] Cross-language hash determinism verified in production

### Platform Integrations
- [ ] GitHub Marketplace trust badges
- [ ] npm install-preflight integration
- [ ] MCP registry trust signals
- [ ] Shopify App Store trust profiles
- [ ] Agent marketplace trust evaluation

### Production Scale
- [ ] 1000+ real entities
- [ ] 10,000+ real receipts
- [ ] Multiple host platform adapters live
- [ ] Dispute system handling real cases
- [ ] Human appeal system with real resolutions

---

## The Constitutional Principle

Everything built under EP must follow one rule:

**Trust must never be more powerful than appeal.**

Every negative trust effect must be explainable, challengeable, and reversible. Power without due process is dangerous.

---

## Mission

From: "The open-source credit score for the agent economy."
To: **"Portable trust for machine counterparties and third-party software."**

Commerce is the first wedge. Software trust is the bigger future. The protocol is the same: receipts, profiles, policies, context, provenance, due process.
