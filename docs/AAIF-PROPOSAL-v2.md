# EMILIA Protocol (EP) — Proposal for AAIF Consideration

EMILIA Protocol is an open protocol for trust decisions and pre-action trust enforcement in machine-mediated systems.

EP Core defines interoperable objects for trust-relevant evidence, trust state, and trust decisions:
- Trust Receipt
- Trust Profile
- Trust Decision

EP Extensions add stronger enforcement where systems must control whether a specific high-risk action should proceed. The most important extension is Handshake, which binds actor identity, authority, policy, action context, nonce, expiry, and one-time consumption into a replay-resistant authorization flow.

When policy requires named human ownership, EP can also require Accountable Signoff before execution.

This proposal asks AAIF to consider EP Core as a minimal interoperable trust-decision interface, while recognizing pre-action enforcement as a key extension area for agent systems operating in high-risk environments.

## Why AAIF should care

As systems move from recommendation to execution, the missing governance layer is not only model quality. It is action control.

MCP tells agents how to use tools. EP tells systems whether a high-risk action should be allowed to proceed.

EP is especially relevant where:
- delegated autonomy intersects with regulated workflows
- high-risk actions require policy-bound, replay-resistant authorization
- human ownership must remain attributable even in agent-assisted systems

## Core question

AAIF should evaluate EP against this question:

> should this exact high-risk action be allowed to proceed in this context, under this policy, by this actor?

That is stronger, more specific, and more interoperable than generic software trust or tool preflight alone.

## Technical foundation

EP is not a proposal. It is a working, audited, production-grade protocol.

**Independent code audit: 100/100** (AAIF automated audit, 2026-04-02)
All 10 categories — formal verification, test quality, documentation, security, CI/CD, developer experience, MCP server, performance, licensing, and production readiness — scored at maximum.

**Formal verification (machine-checked, CI-enforced)**
- 20 TLA+ safety properties verified by TLC model checker (7,857 states, 0 errors) — replay prevention, one-time consumption, delegation acyclicity, concurrent revoke/consume serializability, signoff lifecycle integrity
- 32 Alloy relational facts + 15 assertions verified by Alloy 6.1.0 (0 counterexamples) — structural invariants across all aggregate types
- Both models run automatically in CI on every change to `formal/`

**Test depth**
- 3,277 automated tests across 125 files
- 116 adversarial / red team cases
- 27 fast-check property-based tests covering protocol invariants generatively
- Stryker.js mutation testing with ≥80% kill threshold on protocol core
- Postgres integration tests against a live database in CI

**MCP-native implementation**
- 34 MCP tools across the full EP surface (trust profile, evaluation, handshake, receipt, signoff, commit, dispute, delegation)
- TypeScript and Python SDKs
- OpenAPI spec, linted in CI

**Production readiness**
- Structured JSON logging with correlation IDs (pino-compatible interface, zero console.* in production code)
- Sentry error reporting on client, server, and edge runtimes — PII-scrubbed
- Graceful shutdown: SIGTERM/SIGINT handler drains in-flight writes before exit
- Nonce-based Content Security Policy (no `unsafe-inline` — resolves HIGH-09 pentest finding)
- Kubernetes liveness/readiness probe documentation
- 27 CI quality gates across 12 automated workflows, all actions SHA-pinned for supply chain security
- Handshake create p95: 87ms at 500 concurrent users

**Open source**
- Apache 2.0 license
- All source on GitHub; all formal models, test suites, and CI workflows public
- DCO enforcement on every PR; SBOM and provenance attestation on every release
