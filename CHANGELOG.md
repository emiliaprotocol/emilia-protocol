# Changelog

All notable changes to EMILIA Protocol are documented here.

Versioning model: Protocol spec and reference repo share the root version (1.0.x). SDKs (0.1.x) and MCP server (0.2.x) version independently.

## [Unreleased] — main as of 2026-06-11

### Highlights — the enterprise/protocol build
- **PIP-006 Federation, full** — Operator-B cross-operator client in `@emilia-protocol/verify` 1.3.0 (`verifyFederatedReceipt` / `verifyFederatedReceiptOffline`); `ep-keys.json` advertises `historical_keys` (rotation safety, migration 094), `cache_ttl_seconds`, `verify_url_template`; two-operator conformance harness (`conformance/federation.mjs`) passes against production; Federation Registry convention (`docs/FEDERATION-REGISTRY.md`); formal model `formal/ep_federation.als` — 7 safety assertions, 0 counterexamples, in CI. Remaining acceptance gate: an independent third-party operator.
- **Enterprise SSO** — SAML 2.0 Service Provider + OIDC Relying Party (`app/api/sso/*`, `lib/sso/`, migration 096, `docs/SSO.md`); signature validation via `@node-saml/node-saml` (xml-crypto) and `jose`; fixture-tested including a real signed-SAML-assertion round-trip. Live IdP tenant connected at onboarding.
- **SCIM 2.0 provisioning** — RFC 7643/7644 server (`app/api/scim/v2/*`, `lib/scim/`, migration 095, `docs/SCIM.md`): Users, Groups, filtering, PATCH (both Azure deprovision shapes), per-tenant `ep_scim_` bearer tokens.
- **AML screening** — sanctions/PEP/embargo fail-closed deny; structuring/velocity/near-threshold escalate to accountable signoff; `aml_signals` surfaced on decisions, responses, and audit records (`lib/aml/`, `docs/AML.md`). Live OFAC/EU/UN feeds connected per deployment.
- **Air-gapped installer** — self-contained offline bundle (`deploy/airgap/`): no-egress `internal: true` compose, offline install + migrations, verify scripts proving health + zero-egress + offline receipt verification; CI `airgap-audit` job.
- **Native Secure App** — Expo/React Native signing device (`apps/secure-app/`); its Class-A signoff core is CI-proven to verify under `@emilia-protocol/verify` (tamper + wrong-key rejected). Enclave attestation + app-store publish are the remaining native steps.
- **Self-serve observe-mode pilot** — `/pilot/sandbox`: provision a scoped key, run your own actions through the live adapters in observe mode, pull an automated would-have-been-held report.
- **Amount-tiered escalation** — ≥ $50K single accountable signoff, ≥ $1M dual authorization (`lib/guard-policies.js`).

## [1.1.0] — 2026-04-04

### Highlights
- **3,277 tests** across 125 files — 100/100 audit score (all 10 categories at maximum)
- **EP-IX Identity Continuity** — full state machine: pending → under_challenge → frozen_pending_dispute → terminal; freeze/unfreeze/withdraw operations; rate-limit guard (max 5 open challenges); self-contest guard via ownership graph
- **Protocol Hardening v2** — 9 Supabase migrations (065–073) closing all L99/L90/L75 findings: binding FOR UPDATE, policy version pin, DB-clock expiry, tenant isolation, issuer authority TOCTOU
- **Formal verification extended** — 20 TLA+ properties verified by TLC 2.19 (T1–T20); 6 new EP-IX properties specified (T21–T26); `Claims` constant added to model
- **Audit provenance** — `docs/security/AUDIT_METHODOLOGY.md` documents scope, methodology, 10-category rubric, and reproduction steps
- **API Compatibility Policy** — `docs/api/COMPATIBILITY.md` defines `1.x` stability guarantees, breaking-change policy, and support lifecycle

### Security (migrations 065–073)
- **065**: Unique constraint + trigger on `handshake_bindings` closes TOCTOU double-consumption race
- **066**: `policy_version_number INTEGER` column on `handshakes` enables version pinning
- **067**: `withdrawn` and `frozen_pending_dispute` states added to `continuity_claims` CHECK constraint
- **068**: `policy_rollouts` table for auditable policy deployment history
- **069**: `verify_handshake_writes` RPC — `SELECT ... FOR UPDATE` on binding; returns `already_consumed` signal on race loss
- **070**: `create_handshake_atomic` RPC — `p_policy_version_number` written atomically in same INSERT as handshake row
- **071**: `verify_handshake_writes` RPC — expiry check moved inside FOR UPDATE block using DB `now()` (authoritative clock)
- **072**: `tenant_id UUID` added to `signoff_challenges`, `signoff_attestations`, `handshake_policies`, `policy_versions`
- **073**: `present_handshake_writes` RPC — issuer authority re-checked under `SELECT ... FOR UPDATE`; overrides `verified=false` if race detected

### Protocol
- `checkBinding()` — symmetric `nonce_required` guard: binding nonce presence requires caller to supply nonce (closes nonce-omission bypass)
- `verify.js` — `policy_version_pin_mismatch` check added after policy hash check
- `ep-ix.js` — `freezeContinuityOnDispute()`, `unfreezeResolvedContinuity()`, `withdrawContinuityClaim()` operations; `resolveContinuity()` blocks frozen and withdrawn states; `expireContinuityClaims()` excludes frozen
- `scoring-v2.js` — named constants exported: `DAMPENING_THRESHOLD`, `ESTABLISHMENT_EVIDENCE_GATE`, `ESTABLISHMENT_MIN_SUBMITTERS`, `MAX_UNESTABLISHED_AGGREGATE_CONTRIBUTION`, `MAX_SINGLE_SUBMITTER_CONTRIBUTION`
- `dispute-adjudication.js` — sort uses `CONFIDENCE_WEIGHT_INT` integer comparison (eliminates float non-determinism)
- `constants.js` — `CONTINUITY_STATUS` extended with `FROZEN_PENDING_DISPUTE` and `WITHDRAWN`

### Testing
- **3,277 tests** across 125 files (up from 3,251)
- New test files: `protocol-hardening-v2.test.js` (26 tests covering scoring constants, nonce omission, CONTINUITY_STATUS completeness)
- Load test: `load-tests/binding-lock-contention.js` — 3-scenario k6 test for FOR UPDATE contention benchmarking

### Operational
- `docs/security/AUDIT_METHODOLOGY.md` — full audit scope, methodology, 10-category rubric, findings summary, reproduction steps
- `docs/api/COMPATIBILITY.md` — `1.x` stability guarantees and breaking-change policy
- `docs/api/ERRORS.md` — 12 new/clarified error codes including `nonce_required`, `authority_revoked_at_write`, `policy_version_pin_mismatch`
- `docs/operations/OBSERVABILITY.md` — §10–12: new security check rate metrics, FOR UPDATE contention signal, EP-IX monitoring
- `docs/operations/MIGRATION_RUNBOOK_065_073.md` — ordered rollout guide for migrations 065–073 with verify queries and rollback procedures
- `formal/PROOF_STATUS.md` — updated to reflect 26 total TLA+ properties (20 verified, 6 EP-IX specified)

---

## [1.0.0] — 2026-03-18

### Highlights
- **29 MCP tools**, 4 resources, 3 prompts (up from 24 tools)
- **670 tests** across 28 files — all passing
- **OpenAPI** 50/50 route coverage (every route documented)
- **RFC 7807** canonical error envelope on all API surfaces
- **Canonical TrustDecision** object returned by every evaluation path
- **6-job CI pipeline**: tests, build, lint, SDK builds, conformance, integration
- **TypeScript SDK** (25 methods) + **Python SDK** (21 methods) — published on npm / PyPI
- **EP Commit** — signed pre-action authorization tokens proving policy evaluation before proceeding (5 new tools: ep_issue_commit, ep_verify_commit, ep_get_commit_status, ep_revoke_commit, ep_bind_receipt_to_commit)
- **Commitment proofs**, auto-receipts, delegation chains, attribution tracking, domain scoring
- **Protocol Standard v1.0** — 17 sections, complete specification

### MCP Server (v1.0.0)
- 29 tools: trust evaluation, receipt submission, entity lookup, dispute lifecycle, policy management, identity continuity, software trust, commitment proofs, delegation, attribution, domain scoring, EP Commit, and more
- 4 resources: trust-profile, entity-history, policy-config, system-health
- 3 prompts: evaluate-trust, submit-receipt, investigate-entity
- RFC 7807 error responses on all tool failures
- Auto-receipt generation on trust-changing operations

### SDKs
- TypeScript SDK: 25 methods, full MCP tool coverage, published on npm
- Python SDK: 21 methods, full MCP tool coverage, published on PyPI

### Testing
- 670 tests across 28 test files
- Conformance suite, integration tests, SDK tests, MCP tool tests
- Cross-language hash verification (JS + Python)

---

## [0.9.0] — 2026-03-15 (pre-release)

### Core
- Canonical evaluator — single read brain across all trust surfaces
- Canonical writer — single write brain for all trust-changing operations
- Four-factor receipt weighting: submitter × time × graph × provenance
- Effective-evidence dampening with Sybil quality gate
- Trust profile materialization (snapshot on write, freshness on read)
- Anomaly detection (trust velocity)

### Trust Policies
- 8 policies: strict, standard, permissive, discovery + 4 software-specific
- Policy registry API (GET /api/policies)

### Software Trust (EP-SX)
- Pre-action enforcement (experimental): allow/review/deny for software entities
- Host adapters: GitHub Apps, npm packages, MCP servers, Chrome extensions

### Identity Continuity (EP-IX)
- Spec complete (v0.2)
- Runtime skeleton: migration, lib, 7 API routes
- Continuity-aware evaluator: lineage, inherited disputes, whitewashing flags

### Procedural Justice (Layer 3)
- Dispute lifecycle: 10-state formal state machine
- Human appeal (POST /api/disputes/report, no auth required)
- 7 operator roles with explicit permissions
- Evidence visibility tiers: public, redacted, restricted, operator-only
- Abuse detection: repeated reports, brigading, retaliatory filing, flooding
- Operator audit trail: append-only, before/after state, queryable API
- Reversal propagation: graph_weight → 0, score recomputed

### Evidence Layer
- Receipt pipeline with SHA-256 chain-linked hashing
- Provenance tiers (6 levels, 0.3x–1.0x weight)
- Bilateral attestations (confirm/dispute, 48h window)
- Graph analysis: closed-loop, thin-graph, cluster detection
- DB immutability triggers

### Distribution
- MCP server: 15 tools (initial release; see 1.0.0 for current count)
- Reference SDKs: TypeScript + Python (initial release)
- Conformance suite: 152 automated checks across 7 suites (initial release)
- Cross-language hash verification (JS + Python)
- CI pipeline: tests, build, lint, SDK builds, conformance

### Infrastructure
- Blockchain anchoring: Merkle roots on Base L2
- Deadline enforcement: bilateral 48h, disputes 7d, continuity 30d
- Health endpoint with subsystem checks
