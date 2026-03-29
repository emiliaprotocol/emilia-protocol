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
- cloud control plane
- regulated vertical packs
- open-source protocol with commercial layers above the repo

## Proof points
- 1,500+ automated tests across 60+ files
- 19 TLA+ safety theorems, 32 Alloy facts, 15 assertions
- 85 red team cases documented; 31 security findings identified and remediated
- Full 7-step Accountable Signoff chain proven end-to-end under load
- 329 complete chains executed with zero correctness violations
- 11/11 post-load-test DB integrity checks passing
- Zero duplicate consumptions, zero orphaned bindings, zero missing events
- All endpoints use single-roundtrip atomic RPCs
- Database: 46 EP-only tables, zero foreign artifacts
- Staircase load tested: 10 → 25 → 50 → 100 → 250 → 500 concurrent users
- 95.4% success rate at 500 VUs on Vercel Pro + Supabase
- Zero write discipline exceptions, 16 CI quality gates
- GitHub release v1.0.0 published
