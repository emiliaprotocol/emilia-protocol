# Financial Institutions Brief

## What's new (June 2026)
- **16 suites / 163 vectors:** JavaScript, Python, and Go same-team ports agree on the public suite; a separately authored Rust verifier rebuilt from pinned public source passes it plus 359 hostile cases. Strict independently attested construction acceptance remains pending.
- **Payment-redirect / BEC defense, demonstrably:** the payee account is *inside* the signed action, so swapping it after approval breaks verification rather than sailing through. Run `npx -y @emilia-protocol/crash-test --scenario procurement` to watch it reject a post-approval account swap, offline.
- **Composition (EP-AEC):** EP now composes with delegation and policy-permit receipts from the broader IETF cluster into one offline ALLOW/DENY — a relying party can require *both* a policy check *and* a named human's authorization, bound to the same action.

## Problem
Many of the most expensive failures in finance happen inside approved-looking workflows. EP strengthens the final mile of authorization before execution.

## Best first workflow
- beneficiary change
- payout destination change
- remittance update
- treasury release approval

## What EP proves before action
- actor identity
- authority chain
- exact transaction binding
- policy version and hash
- replay resistance
- one-time consumption
- accountable signoff when required

## Proof points

| Metric | Result |
|--------|--------|
| **Internal security review (self-administered, see docs/security/AUDIT_METHODOLOGY.md)** | **100/100** (2026-04-02, all 10 categories at maximum) |
| Automated test cases | 5,400 across 265 files; all platform-applicable cases must pass |
| Formal verification | 26 TLA+ properties verified (TLC 2.19, 413,137 states, 0 errors); 35 Alloy facts + 22 assertions (Alloy 6.0.0, 0 counterexamples) — both enforced in CI |
| Mutation testing | ≥80% kill threshold on protocol core (Stryker.js) |
| Red team cases | 116 documented |
| Security findings | 31 identified and remediated |
| Signoff chain | Full 7-step Accountable Signoff proven end-to-end under load |
| Load-test chains | 329 complete, zero correctness violations |
| DB integrity | 11/11 post-load-test checks passing |
| Data discipline | Zero duplicate consumptions, zero orphaned bindings, zero missing events |
| Transaction model | All endpoints use single-roundtrip atomic RPCs; handshake p95 87ms at 500 VUs |
| Database isolation | 46 EP-only tables, zero foreign artifacts |
| CI / supply chain | 27 quality gates, all Actions SHA-pinned, SBOM + provenance on every release |

## Why it matters
This reduces ambiguity in approvals, improves evidence quality, and creates stronger control over high-risk financial changes.
