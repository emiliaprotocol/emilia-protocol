# Government Pilot Proposal — EMILIA GovGuard

## Proposal title
EMILIA GovGuard — pre-execution control for government benefit, payment, and override workflows

## Executive summary

Government programs lose money inside workflows that already pass authentication. The session is valid. The role has the right permissions. The action — a benefit redirect, a caseworker override, a payment destination change — was never bound to an action-level policy and was never owned by a named accountable human. EMILIA GovGuard fills that gap.

GovGuard sits between the agency's existing identity layer and the benefits or payments core system. Before a high-risk change executes, GovGuard binds the actor, the exact action context, the active policy, and the expiry into a one-time trust receipt; if policy requires it, an accountable supervisor must approve the exact action hash before consume. Receipts cannot be replayed, cannot outlive their expiry, and cannot be consumed without the action they authorize.

GovGuard is the productized surface of EMILIA Protocol — Apache 2.0, formally verified, with an internal audit score of 100/100 (self-administered; see `docs/security/AUDIT_METHODOLOGY.md`).

## What ships today (verifiable in `github.com/emiliaprotocol/emilia-protocol`)

### v1 Trust Receipts API — the GovGuard product surface
| Endpoint | Purpose |
|---|---|
| `POST /api/v1/trust-receipts` | Create a trust receipt (precheck + policy eval + audit emit) |
| `GET /api/v1/trust-receipts/{id}` | Read receipt state (replays event log) |
| `POST /api/v1/trust-receipts/{id}/consume` | One-time consume bound to action_hash |
| `GET /api/v1/trust-receipts/{id}/evidence` | Full evidence packet (timeline, signoff trail, consume record) |
| `POST /api/v1/signoffs/request` | Open a signoff request against a pending receipt |
| `POST /api/v1/signoffs/{id}/approve` | Approver acts (self-approval forbidden, action_hash bound) |
| `POST /api/v1/signoffs/{id}/reject` | Approver rejects |

### GovGuard demo adapters
| Endpoint | Workflow |
|---|---|
| `POST /api/v1/adapters/gov/benefit-bank-change/precheck` | Caseworker changes a claimant's benefit bank account |
| `POST /api/v1/adapters/gov/caseworker-override/precheck` | Operator overrides automatic disqualification |

### Enforcement modes (per workflow, per organization)
- **Observe** — evaluate every protected action, log decisions, never block. Generates the audit report that shows what *would* have been blocked.
- **Warn** — return decision to caller; caller chooses whether to honor. Used for staged rollouts.
- **Enforce** — fail closed. Block actions that violate policy or lack required signoff.

### Receipts dashboard
- `/cloud/guard-receipts` — server-rendered admin view: recent receipts, status badges, drill-down to evidence packet.

## Recommended pilot scope

Pick one workflow:
- **Benefit bank-account change** (claimant payment redirect prevention)
- **Caseworker override** (operator action accountability)
- **Delegated case action** (custom — scope per agency)

We will:
1. Wire one workflow into observe mode (no behavior change, full evidence trail).
2. Run the audit report at week 2 and week 4: what would have been blocked, who would have signed off, who would have been notified.
3. If the agency chooses, flip to enforce mode after week 4.

## What the pilot proves
- Replay-resistant authorization at the action layer
- Named human accountability where policy requires it (signoff cannot be self-approved, cannot bind to a different action than the one approved)
- Clearer event traceability — Inspector General / GAO inspectable timeline per receipt
- Policy version pinning — every decision references an immutable policy hash

## Government Reference Pack — what's in it

### Action-level controls (shipped)
- **Payment destination change controls** — require signoff before modifying payment routing, with identity and authority verification at each step
- **Benefits redirect controls** — prevent unauthorized changes to benefit delivery targets, with mandatory accountable signoff
- **Operator override constraints** — scope operator overrides to specific actions, enforce time-limited authority, and log every override with full context
- **Money-destination policy guards** — any change to `bank_account`, `routing_number`, `iban`, `swift_bic`, `beneficiary_name`, or `payment_address` automatically requires signoff (configurable per workflow)
- **Hard-deny risk flags** — `impossible_travel`, `known_compromised_device` deny outright with no signoff path

### Audit evidence export (shipped)
- `GET /api/v1/trust-receipts/{id}/evidence` returns the full evidence packet for a single receipt
- `/api/cloud/audit/export` exports raw event streams, policy snapshots, and signoff records for a time range or workflow
- `/api/cloud/audit/report` generates formatted evidence packages with control-to-event traceability and policy compliance summaries

### Roadmap (pilot-track, scoped per engagement)
- **PIV/CAC/Login.gov identity integration** — pilots needing federal-credential integration today get it scoped as part of the engagement; not shipped off-the-shelf.
- **FISMA/FedRAMP compliance mapping** — control-family mapping documents are not yet published. EP enforcement satisfies action-level accountability requirements that map onto multiple NIST 800-53 controls; the formal mapping document is on the roadmap.

## Proof points

- 3,483 automated tests across 132 test files (`npx vitest run`)
- 26 TLA+ safety properties verified (T1–T26, TLC 2.19, 413,137 states, 0 errors) — including the EP-IX identity continuity invariants
- 85 red team cases cataloged in `docs/conformance/RED_TEAM_CASES.md`
- 35 Alloy facts + 15 assertions verified (Alloy 6.0.0, 0 counterexamples)
- Zero write-discipline exceptions
- Append-only event store with DB-level immutability triggers
- One-time consumption enforced at both the application and the database level
- 38 NIST AI RMF subcategories mapped across all four functions; EU AI Act Articles 9–15 + 26 mapped
- Internal security audit: 100/100 self-administered (see `docs/security/AUDIT_METHODOLOGY.md`); third-party engagement planned

## Pilot outputs

- Control architecture for the selected workflow
- Pilot policy pack (action types, signoff thresholds, hard-deny flags)
- Verification and signoff flow walkthrough (with adversarial test cases)
- Event and evidence export — IG/GAO inspectable
- 30-day success metrics: receipts issued, signoffs requested, signoff response time, would-have-been-blocked counts (observe mode), actually-blocked counts (enforce mode)
- Implementation notes for transition to production
