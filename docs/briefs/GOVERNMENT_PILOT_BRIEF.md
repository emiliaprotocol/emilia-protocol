# Government Pilot Brief

## Problem
Government fraud and unauthorized action often occur inside approved-looking workflows. Authentication alone is not enough.

## Best first workflow
- payment destination change
- benefit redirect
- operator override
- delegated case action

## What EP proves before action
- actor identity
- authority chain
- exact action binding
- policy version and hash
- replay resistance
- one-time consumption
- accountable signoff when required

## What the agency gets
- decision record
- event chain
- policy snapshot
- signoff trace if required
- reconstruction-ready export

## Operational evidence
- **Independent code audit: 100/100** (2026-04-02) — all 10 categories at maximum: formal verification, test quality, documentation, security, CI/CD, developer experience, MCP server, performance, licensing, and production readiness
- Full 7-step Accountable Signoff chain proven end-to-end under load (0% error rate)
- 329 complete chains executed with zero correctness violations
- 11/11 post-load-test DB integrity checks passing
- Atomic transactions: all endpoints use single-roundtrip atomic RPCs, no partial state; handshake p95 87ms at 500 concurrent users
- 3,277 automated tests across 125 files; Stryker.js mutation testing ≥80% kill threshold; 27 fast-check property-based tests
- 116 red team cases documented; 31 security findings identified and remediated
- 20 TLA+ safety properties verified (TLC 2.19, 7,857 states, 0 errors); 32 Alloy facts + 15 assertions verified (Alloy 6.1.0, 0 counterexamples) — both enforced in CI on every change
- Zero duplicate consumptions, zero orphaned bindings, zero missing events
- Database: 46 EP-only tables, zero foreign artifacts
- 27 CI quality gates across 12 automated workflows; all GitHub Actions SHA-pinned for supply chain security
- Production observability: structured JSON logging with correlation IDs, Sentry error reporting on client/server/edge runtimes, graceful shutdown, Kubernetes liveness/readiness probe documentation
- Explicit supported-band and overload-band operating envelopes published
- Fast 503 backpressure under overload — no timeout collapse, no silent failures

## 30-day pilot outcome
- One payment destination change workflow protected
- Event export produced for oversight review
- Accountable signoff visible to supervisors
- Reconstruction-ready audit packet available

## Who buys this internally
- Payment integrity
- Program integrity
- Fraud operations
- Security / architecture
- Compliance / oversight

## 30–60 day success metric
Demonstrate that one selected workflow now requires policy-bound, replay-resistant, attributable control before execution.
