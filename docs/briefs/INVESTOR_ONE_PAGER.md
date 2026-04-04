# EP Investor One-Pager

## What EP is
EMILIA Protocol (EP) is a protocol-grade trust substrate for high-risk action enforcement.

EP creates the control layer between authentication and execution. It determines whether a specific actor, under a specific authority chain, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance and immutable event traceability.

## Why now
- fraud is moving inside approved-looking workflows
- AI and automation increase execution risk
- buyers increasingly need evidence, not assertions

## What is defensible
- canonical action binding
- one-time consumption
- Accountable Signoff
- MCP-native implementation (34 tools, TypeScript + Python SDKs)
- production observability stack (structured JSON logging, Sentry on 3 runtimes)
- supply chain security (SHA-pinned Actions, SBOM, provenance attestation)
- cloud control plane
- regulated vertical packs
- open-source protocol with commercial layers above the repo

## Proof points
- **Independent code audit: 100/100** (2026-04-02) — 10/10 categories at maximum
- 3,277 automated tests across 125 files
- 20 TLA+ safety properties verified (TLC 2.19, 7,857 states, 0 errors); 32 Alloy facts + 15 assertions verified (Alloy 6.1.0, 0 counterexamples) — both run in CI on every change
- Stryker.js mutation testing — ≥80% kill threshold on protocol core; 27 fast-check property-based tests
- 116 red team cases documented; 31 security findings identified and remediated
- Full 7-step Accountable Signoff chain proven end-to-end under load
- 329 complete chains executed with zero correctness violations
- 11/11 post-load-test DB integrity checks passing
- Zero duplicate consumptions, zero orphaned bindings, zero missing events
- All endpoints use single-roundtrip atomic RPCs
- Database: 46 EP-only tables, zero foreign artifacts
- Staircase load tested: 10 → 50 → 100 → 200 → 500 concurrent users; handshake create p95 87ms
- Zero write discipline exceptions, 27 CI quality gates across 12 automated workflows, all Actions SHA-pinned
- Apache 2.0 license, DCO enforcement on every PR, SBOM + provenance attestation on every release
- GitHub release v1.0.0 published
