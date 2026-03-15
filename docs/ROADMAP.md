# EP Master Roadmap

**Updated:** March 2026
**Mission:** Portable trust evaluation and appeals for principals in machine-mediated systems.
**One-line:** Freeze the trust core, ship identity continuity, formalize human procedure, add host adapters, turn policies into a platform.

---

## What's Built (Shipped)

### Trust Engine
- [x] Canonical evaluator — one read brain across all 10 trust surfaces
- [x] Canonical writer — one write brain for all trust-changing actions
- [x] Behavioral-first v2 weights (behavioral 40%, consistency 25%)
- [x] Four-factor receipt weighting: submitter × time × graph × provenance
- [x] Effective-evidence dampening (Sybil resistance)
- [x] Trust profiles as canonical output
- [x] Policy evaluation (strict/standard/permissive/discovery + custom JSONB)
- [x] Context-aware evaluation with global fallback
- [x] Anomaly detection (trust velocity)
- [x] Provenance tiers (6 levels, 0.3x–1.0x weight)
- [x] Bilateral attestations (confirm/dispute, 48h window)
- [x] Trust profile materialization (snapshot on write, freshness on read)

### Receipt System
- [x] Canonical receipt pipeline (createReceipt → canonicalSubmitReceipt)
- [x] SHA-256 chain-linked hashing with canonical JSON
- [x] Context keys (task_type, category, geo, modality, value_band, risk_class)
- [x] DB immutability triggers
- [x] Provenance tier on every receipt
- [x] Bilateral confirmation endpoint

### Sybil Resistance
- [x] Graph analysis (closed-loop 0.4x, thin-graph 0.5x, cluster 0.1x)
- [x] Submitter credibility (unestablished = 0.1x)
- [x] Effective-evidence dampening
- [x] Server-derived owner_id (SHA-256 of client IP)
- [x] Identity-aware rate limiting

### Due Process
- [x] Dispute lifecycle (open → under_review → upheld/reversed/dismissed)
- [x] Human appeal (POST /api/disputes/report, no auth)
- [x] Human appeal page (/appeal)
- [x] Reversal propagation (graph_weight → 0, score recomputed)
- [x] Dispute rate limiting (5/hr disputes, 3/hr reports)

### Software Trust (EP-SX)
- [x] Install preflight (POST /api/trust/install-preflight)
- [x] Software entity types (github_app, mcp_server, npm_package, chrome_extension, etc.)
- [x] 4 software policies (github_private_repo_safe, npm_buildtime_safe, browser_extension_safe, mcp_server_safe)
- [x] Host adapter stubs (GitHub, npm, MCP, Chrome)

### Operational Infrastructure
- [x] /api/health — protocol version, DB/Redis/anchor status, counts
- [x] /api/cron/expire — bilateral timeout (48h) + dispute escalation (7 days)
- [x] Well-known discovery (/.well-known/ep-trust.json)

### Distribution
- [x] MCP server (14 tools, trust-native, context-aware)
- [x] Reference SDKs (TypeScript + Python, source-only)
- [x] SDK publish workflows (npm + PyPI)

### Conformance
- [x] 145 tests across 7 test suites
- [x] 14 adversarial tests (Sybil, reciprocal loops, cluster collusion, trust farming)
- [x] Trust profile determinism fixtures
- [x] Cross-language hash verification (JavaScript + Python)
- [x] CI pipeline (GitHub Actions)

### Docs & Governance
- [x] EP Core RFC v1.1
- [x] THE-EROSION-OF-TRUST.md — manifesto
- [x] EP-IX Identity Continuity Extension (spec, v0.2)
- [x] EP-SX Software Trust Extension
- [x] AAIF working group proposal
- [x] NIST engagement plan
- [x] SECURITY.md — full threat model
- [x] STYLE-GUIDE.md — canonical vocabulary
- [x] CANONICAL-DOCS.md — document map
- [x] GOVERNANCE.md, CONTRIBUTING.md

---

## Phase 1: Ship & Prove (Now — April 2)

**Goal:** Get EP in front of real people. Everything else is preparation for this.

### Human Actions (not code)
- [ ] Send AAIF email (docs/OUTREACH-EMAILS.md)
- [ ] Send NIST email (docs/OUTREACH-EMAILS.md)
- [ ] Run migration 018 in Supabase (trust_snapshot + trust_materialized_at)
- [ ] Push all batches to GitHub, verify live site matches repo
- [ ] Prepare MCP Dev Summit demo (April 2-3, NYC)
- [ ] Get 3-5 developers to register entities at the summit
- [ ] Get 1 external entity submitting real receipts

### Operational
- [ ] Set up Upstash Redis (production rate limiting)
- [ ] Verify /api/health returns healthy on production
- [ ] Verify /api/cron/expire runs on Vercel schedule
- [ ] Wire RexRuby to submit real receipts (blocked on Twilio)
- [ ] Add spec.emiliaprotocol.ai CNAME

### Build
- [x] Human trust console (search + profile + preflight UI on landing page)
- [ ] Summit demo script (ChatGPT to draft)

**Success condition:** One external entity submits a real receipt. EP stops being internally excellent and becomes externally real.

### Proof Track (parallel)
- [ ] Publish conformance status on README (live vs spec vs planned)
- [ ] Expand adversarial tests to cover EP-IX continuity scenarios
- [ ] Add e2e dispute → appeal → reversal proof test
- [ ] Add continuity test vectors to conformance fixtures
- [ ] Document public implementation status at every phase gate

---

## Phase 2: EP-IX Runtime (Weeks 3-6)

**Goal:** Trust can no longer be cheaply reset by re-registration.

### Data Model
- [ ] `principals` table (principal_id, type, status, bootstrap_verified)
- [ ] `identity_bindings` table (binding_type, target, proof_type, provenance, status)
- [ ] `continuity_claims` table (old/new entity, reason, mode, status, challenge_deadline, expires_at)
- [ ] `continuity_challenges` table
- [ ] `continuity_decisions` table (decision, transfer_policy, allocation_rule, reasoning)
- [ ] `continuity_events` table (audit trail)

### API Surface
- [ ] POST /api/identity/bind
- [ ] POST /api/identity/verify
- [ ] POST /api/identity/continuity
- [ ] POST /api/identity/continuity/challenge
- [ ] POST /api/identity/continuity/resolve
- [ ] GET /api/identity/principal/:principalId
- [ ] GET /api/identity/lineage/:entityId

### Evaluator Integration
- [ ] Continuity-aware trust profile output (lineage, inherited disputes, whitewashing flag)
- [ ] Install preflight: fail on suspicious continuity gaps

### Deadline Enforcement
- [ ] Challenge window expiry (7 days) in cron
- [ ] Continuity claim expiry (30 days) in cron
- [ ] Dispute freeze rules on continuity

**Success condition:** A principal can rotate keys without losing trust. A bad actor cannot cheaply re-register to escape history.

---

## Phase 3: Human Procedural Layer (Month 2-3)

**Goal:** EP becomes an institution, not just a protocol.

### Roles
- [ ] Explicit role model: reporter, disputant, respondent, reviewer, appeal reviewer, operator, host verifier
- [ ] Operator trust profiles (operators are entities, their performance is measurable)

### Evidence Visibility
- [ ] Visibility tiers: public summary, redacted public, restricted, operator-only
- [ ] `visibility_level` and `redaction_status` fields on dispute/report objects
- [ ] Evidence redaction API

### State Machines
- [ ] Formal dispute state machine (not loose status strings)
- [ ] Formal appeal state machine
- [ ] Formal continuity challenge state machine
- [ ] State transition validation (invalid transitions rejected)

### Operator Auditability
- [ ] Audit event on every trust-changing operator action
- [ ] Before/after state capture
- [ ] Linked object IDs
- [ ] Queryable audit log API

### Abuse Controls
- [ ] Write throttling classes (reports, disputes, appeals, operator actions)
- [ ] Abuse heuristics: repeated identical reports, brigading, retaliatory filing, challenge spam

**Success condition:** Trust can be challenged and corrected safely, without mob dynamics. Operators are accountable.

---

## Phase 4: Host Adapters (Month 2-4)

**Goal:** EP becomes useful where trust decisions already happen.

### GitHub Adapter
- [ ] GitHub App metadata ingestor (permissions, scope, publisher verification)
- [ ] GitHub org binding verifier
- [ ] Installation webhook receiver
- [ ] Revocation signals

### MCP Adapter
- [ ] Server card ingestion
- [ ] Registry listing status
- [ ] Capability extraction
- [ ] Install/use preflight integration

### npm Adapter
- [ ] Trusted publishing verification
- [ ] Provenance linkage
- [ ] Publisher identity binding
- [ ] Package incident events

### Commerce Adapter (Shopify)
- [ ] Shopify webhook subscription (order lifecycle)
- [ ] Receipt generation from order events
- [ ] Returns/refunds signals
- [ ] Merchant trust profile updates

### Browser Extension Adapter (later)
- [ ] Store review state
- [ ] Declared permissions
- [ ] Warning classes
- [ ] Uninstall/revoke signals

**Success condition:** EP produces trust profiles from real ecosystem events, not just API calls.

---

## Phase 5: Human Mode (Month 3-5)

**Goal:** Humans can use EP directly without needing an agent.

### Human Trust Console
- [ ] Search any entity
- [ ] View full trust profile
- [ ] Run policy evaluation
- [ ] Run install preflight
- [ ] See dispute history
- [ ] File report / appeal
- [ ] Principal lineage view

### Procurement / Approval Mode
- [ ] "Approve this plugin" workflow
- [ ] "Approve this vendor" workflow
- [ ] "Approve this MCP server" workflow
- [ ] Enterprise policy integration API

### Principal View
- [ ] Trust profile + lineage + continuity + disputes + sanctions
- [ ] Install/preflight status
- [ ] Public evidence summaries

**Success condition:** A human IT admin can evaluate whether to install a GitHub App using EP without writing code.

---

## Phase 6: Policy Platform (Month 4-6)

**Goal:** Policies become a managed, versioned, shareable system.

### Policy Registry
- [ ] GET /api/policies — list available policies
- [ ] POST /api/policies — register custom policy
- [ ] Policy versioning and deprecation
- [ ] Policy signatures
- [ ] Policy visibility controls

### Policy Families
- [ ] Commerce trust policies
- [ ] Install preflight policies (per host type)
- [ ] Marketplace seller/app approval policies
- [ ] MCP server safety policies
- [ ] npm/GitHub package safety policies

### Policy Explanations
- [ ] For every result: pass/review/fail + reasons + failed controls + missing evidence + continuity concerns + dispute burden

**Success condition:** EP becomes a system people make decisions with, not just inspect.

---

## Phase 7: Trust Analytics & Monitoring (Month 5-8)

**Goal:** Trust itself becomes observable and governable.

### Build
- [ ] Trust profile history (time series)
- [ ] Anomaly stream
- [ ] Dispute burden dashboards
- [ ] Continuity graph views
- [ ] Whitewashing alerts
- [ ] Provenance mix analytics
- [ ] Install preflight failure reasons by host

**Success condition:** Enterprise operators can monitor trust health across their ecosystem.

---

## Phase 8: Standardization & Institutional Maturity (Month 6-12)

**Goal:** An outsider can implement EP without you.

### Conformance Infrastructure
- [ ] Public conformance docs site
- [ ] Versioned spec publishing flow
- [ ] "How to certify your implementation" guide
- [ ] Minimal implementation guide for outside builders
- [ ] Canonical test vectors for: trust profiles, disputes, appeals, continuity, install preflight

### Governance
- [ ] First external implementation passes conformance suite
- [ ] AAIF working group established (or equivalent)
- [ ] Spec v2.0 (formal object model)
- [ ] Independent security audit
- [ ] **Standards track:** W3C/IETF draft for Agent Trust standard (requires adoption evidence)

### Institutional
- [ ] Multi-maintainer governance
- [ ] Conformance certification program
- [ ] Public operator accountability metrics
- [ ] Archive policy for deprecated specs

**Success condition:** EP is a standard, not a project. Multiple implementations exist. Governance is shared.

---

## The Vision

EP becomes the default answer to:
- Should I trust this merchant?
- Should I install this plugin?
- Should I connect to this MCP server?
- Should I route to this seller?
- Should I trust this software maintainer after a migration?
- If this judgment is wrong, how is it challenged and corrected?

**The operating system for contested trust in machine-mediated systems.**

---

*EMILIA Protocol — Trust evaluation and appeals for principals in machine-mediated systems.*
