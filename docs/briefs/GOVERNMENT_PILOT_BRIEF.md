# Government Pilot Brief

## What's new (June 2026)
- **17 suites / 192 vectors across three same-team language ports**, plus a separately authored Rust verifier rebuilt from pinned public source and tested against 359 hostile cases — external interoperability evidence a relying party can reproduce without trusting the vendor.
- **Composition (EP-AEC):** EP composes delegation + policy-permit + human-authorization receipts into one offline ALLOW/DENY — the convergence layer for the emerging IETF agent-authorization standards, not one of a dozen competing formats.
- **Regulated-domain reach:** EU AI Act Article 14 alignment plus a healthcare profile (the mandated independent double-check, PHI-free receipts) extend the same primitive across oversight regimes.

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
- **Internal security review (self-administered, see docs/security/AUDIT_METHODOLOGY.md): 100/100** (2026-04-02) — all 10 categories at maximum: formal verification, test quality, documentation, security, CI/CD, developer experience, MCP server, performance, licensing, and production readiness
- Full 7-step Accountable Signoff chain proven end-to-end under load (0% error rate)
- 329 complete chains executed with zero correctness violations
- 11/11 post-load-test DB integrity checks passing
- Atomic transactions: all endpoints use single-roundtrip atomic RPCs, no partial state; handshake p95 87ms at 500 concurrent users
- 5,000+ automated test cases across 250+ files, with all platform-applicable cases required to pass; Stryker.js mutation gate ≥90%; property-based and linearizability testing included
- 85 red team cases documented; 31 security findings identified and remediated
- 26 TLA+ safety properties verified (TLC 2.19, 413,137 states, 0 errors); 35 Alloy facts + 22 assertions verified (Alloy 6.0.0, 0 counterexamples) — both enforced in CI on every change
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
