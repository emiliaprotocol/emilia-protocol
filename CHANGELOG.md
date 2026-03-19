# Changelog

All notable changes to EMILIA Protocol are documented here.

Versioning model: Protocol spec and reference repo share the root version (1.0.x). SDKs (0.1.x) and MCP server (0.2.x) version independently.

## [1.0.0] — 2026-03-18

### Highlights
- **24 MCP tools**, 4 resources, 3 prompts (up from 15 tools)
- **670 tests** across 28 files — all passing
- **OpenAPI** 50/50 route coverage (every route documented)
- **RFC 7807** canonical error envelope on all API surfaces
- **Canonical TrustDecision** object returned by every evaluation path
- **6-job CI pipeline**: tests, build, lint, SDK builds, conformance, integration
- **TypeScript SDK** (25 methods) + **Python SDK** (21 methods) — published on npm / PyPI
- **ZK proofs**, auto-receipts, delegation chains, attribution tracking, domain scoring
- **Protocol Standard v1.0** — 17 sections, complete specification

### MCP Server (v1.0.0)
- 24 tools: trust evaluation, receipt submission, entity lookup, dispute lifecycle, policy management, identity continuity, software trust, ZK proofs, delegation, attribution, domain scoring, and more
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
- Install preflight: allow/review/deny for software entities
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
