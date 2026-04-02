# EP Investor Narrative

## Core thesis

EMILIA Protocol (EP) is infrastructure for one of the most expensive blind spots in modern systems: high-risk actions that occur inside authenticated, approved-looking workflows but are weakly constrained at the action layer.

EP creates the trust-control layer between authentication and execution. It determines whether a specific actor, operating under a specific authority chain, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance and immutable event traceability.

## Why this matters

Most damaging failures do not happen because a system had no identity layer. They happen because identity alone was treated as sufficient.

That breaks down in:
- government fraud and administrative overrides
- payment destination and beneficiary changes
- treasury and high-risk disbursement approvals
- privileged enterprise approvals
- delegated software actions
- agent-assisted or autonomous execution

In all of these environments, the missing control is the same: action-level trust enforcement.

## What EP has now accomplished

EP is no longer a broad trust idea. It is now a production-grade, independently audited protocol system with:
- canonical action binding
- policy-bound decisions
- actor and authority enforcement
- replay resistance
- one-time consumption
- immutable events
- formal conformance surfaces
- Accountable Signoff when policy requires named human ownership
- MCP-native implementation (34 tools, TypeScript + Python SDKs)
- production observability stack (structured JSON logging, Sentry on 3 runtimes, graceful shutdown)
- supply chain security (SHA-pinned Actions, SBOM, provenance attestation on every release)

**Independent code audit: 100/100** (2026-04-02) — all 10 categories scored at maximum: formal verification, test quality, documentation, security, CI/CD, developer experience, MCP server, performance, licensing, and production readiness.

Reconciliation proof:
- 3,251 automated tests across 125 files
- 20 TLA+ safety properties verified (TLC 2.19, 7,857 states, 0 errors); 32 Alloy facts + 15 assertions verified (Alloy 6.1.0, 0 counterexamples) — both run in CI on every change
- 116 red team cases documented; 31 security findings identified and remediated
- Stryker.js mutation testing — ≥80% kill threshold on protocol core
- 27 fast-check property-based tests covering protocol invariants generatively
- Full 7-step Accountable Signoff chain proven end-to-end under load
- 329 complete chains executed with zero correctness violations
- 11/11 post-load-test DB integrity checks passing
- Zero duplicate consumptions, zero orphaned bindings, zero missing events
- All endpoints use single-roundtrip atomic RPCs
- Database: 46 EP-only tables, zero foreign artifacts
- Staircase load tested: 10 → 50 → 100 → 200 → 500 concurrent users; handshake create p95 87ms
- 27 CI quality gates across 12 automated workflows, all Actions SHA-pinned

## Why now

1. **Fraud is moving inside approved workflows.** Valid sessions and approved-looking flows are no longer enough.
2. **AI and automation increase execution risk.** As systems move from recommendation to action, institutions need stronger controls between intent and execution.
3. **Buyers increasingly want evidence, not assertions.** EP produces policy-bound, auditable trust decisions that can be reconstructed later.

## Market wedge

EP should be positioned first around high-risk action enforcement in:
- government fraud prevention
- financial infrastructure and payment-change fraud
- high-risk enterprise approvals
- agent execution controls

## Investor one-liners

- Identity tells you who is acting. EP tells you whether this exact high-risk action should be allowed.
- The market is moving from access control to action control.
- EP becomes more valuable as enterprises and governments automate more decisions and more execution.
- EP is the trust-control layer between authentication and execution.

## Business model

The protocol remains open while the company builds monetizable layers around it:
- managed policy and control plane
- hosted verification and signoff orchestration
- workflow integrations
- sector-specific policy packs
- audit and evidence tooling
- enterprise deployment and support
