# Changelog

All notable changes to EMILIA Protocol are documented here.

Versioning model: Protocol spec and reference repo share the root version (1.0.x). SDKs (0.1.x) and MCP server (0.2.x) version independently.

## [1.0.0] — 2026-03-15

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
- MCP server: 15 tools
- Reference SDKs: TypeScript + Python (published on npm and PyPI)
- Conformance suite: 152 automated checks across 7 suites
- Cross-language hash verification (JS + Python)
- CI pipeline: tests, build, lint, SDK builds, conformance

### Infrastructure
- Blockchain anchoring: Merkle roots on Base L2
- Deadline enforcement: bilateral 48h, disputes 7d, continuity 30d
- Health endpoint with subsystem checks
