# Financial Institutions Pilot Proposal — EMILIA FinGuard

## Proposal title
EMILIA FinGuard — pre-execution trust for beneficiary changes, vendor remittance updates, payout-destination changes, and treasury release approvals

## Executive summary

The most expensive failures in finance happen inside approved-looking workflows. The session is authenticated. The role has the right permissions. The form passes validation. None of that detects that the vendor's bank account was swapped 90 seconds before the wire is released. EMILIA FinGuard binds the wire to the exact pre-change state. Anything else fails consume.

FinGuard sits between the AP/treasury system's authentication layer and the SWIFT/ACH/Fedwire/RTP/internal release rails. Before a beneficiary, vendor, or payout instruction change executes — and before any large payment release lands — FinGuard issues a one-time, action-bound trust receipt with a policy-pinned hash, an expiry, and (when policy requires it) a mandatory accountable signoff. The receipt cannot be replayed, cannot outlive its expiry, and cannot be consumed without the action it authorizes.

FinGuard is the productized surface of EMILIA Protocol — Apache 2.0, formally verified, with an internal audit score of 100/100 (self-administered).

## What ships today (verifiable in `github.com/emiliaprotocol/emilia-protocol`)

### v1 Trust Receipts API — same surface as GovGuard
| Endpoint | Purpose |
|---|---|
| `POST /api/v1/trust-receipts` | Create receipt (precheck + policy eval + audit emit) |
| `GET /api/v1/trust-receipts/{id}` | Read state (replays event log) |
| `POST /api/v1/trust-receipts/{id}/consume` | One-time consume bound to action_hash |
| `GET /api/v1/trust-receipts/{id}/evidence` | Full SOX-ready evidence packet |
| `POST /api/v1/signoffs/request` | Open signoff request |
| `POST /api/v1/signoffs/{id}/approve` | Approver acts (self-approval forbidden, action_hash bound) |
| `POST /api/v1/signoffs/{id}/reject` | Approver rejects |

### FinGuard demo adapters
| Endpoint | Workflow |
|---|---|
| `POST /api/v1/adapters/fin/vendor-bank-change/precheck` | AP user changes vendor bank account |
| `POST /api/v1/adapters/fin/beneficiary-creation/precheck` | New SWIFT-eligible counterparty added |
| `POST /api/v1/adapters/fin/payment-release/precheck` | Treasury releases wire above amount threshold |

### Enforcement modes (per workflow, per organization)
- **Observe** — evaluate every protected action, log decisions, never block. Generates the audit report that shows what *would* have been blocked.
- **Warn** — return decision to caller; caller chooses whether to honor. Used for staged rollouts.
- **Enforce** — fail closed.

## Recommended pilot scope

Pick one workflow:
- **Beneficiary change** before SWIFT/wire release
- **Payout destination change** in AP/treasury systems
- **Vendor remittance update**
- **Large payment release approval** (threshold-based)

We will:
1. Wire one workflow into observe mode (no behavior change, full evidence trail).
2. Run the audit report at week 2 and week 4: what would have been blocked, who would have signed off, who would have been notified.
3. If the institution chooses, flip to enforce mode after week 4.

## What the pilot proves

- **Exact transaction binding** — every receipt pins the canonical action shape via SHA-256 over a sorted-key payload. Tampering between issuance and consume fails the action_hash check.
- **Replay-resistant authorization** — receipts consume exactly once at both the application and database level (UNIQUE-constraint + immutability trigger).
- **Policy-bound approvals** — each receipt references an immutable policy hash; policy changes produce a new hash, breaking any in-flight receipts that referenced the old version.
- **Better audit evidence** — every state transition is recorded in `audit_events` with DB-level immutability triggers. Auditor-grade timeline per receipt.
- **Accountable signoff for higher-risk thresholds** — money-destination changes, AI-agent-initiated payments, and payments above $50K (configurable) require named human signoff. Self-approval is rejected by code (the initiator cannot also be the approver).

## Capabilities now implemented

### Money-destination policy guards
Any change to `bank_account`, `routing_number`, `iban`, `swift_bic`, `beneficiary_name`, or `payment_address` automatically requires accountable signoff. This is enforced in `lib/guard-policies.js` and exercised by the unit suite — not a design-stage feature.

### Amount-based escalation
The policy engine supports threshold-based escalation matrices. The shipped default: payments ≥ $50K require accountable signoff. Thresholds are configurable per workflow; pilots commonly set "≥ $1M requires out-of-band verification" as an additional layer.

### Dual signoff for treasury operations
Two authorized signers must independently attest before a high-value transaction executes. Each attestation is cryptographically bound to the exact transaction details. The signoff flow enforces self-approval prevention — the initiator cannot also be the approver — and binds approvals to the exact action_hash, so an approval issued for one action cannot be silently applied to another.

### SOX-ready evidence export
- `GET /api/v1/trust-receipts/{id}/evidence` returns the full evidence packet for a single receipt: actor, action hashes, policy version, decision rationale, signoff trail (request + approve/reject + approver identity), consume record, complete event timeline.
- `/api/cloud/audit/export` generates compliance packages containing complete event timelines, policy snapshots, binding material, and verification results — ready for auditor consumption without manual assembly.

### Wire transfer protection patterns
The Financial Reference Pack includes pre-built policy configurations for the highest-risk wire transfer scenarios: beneficiary changes, remittance changes, payout destination changes, and AI-agent-initiated payment actions. These patterns are documented and ready to deploy via the FinGuard adapters above.

### AI-agent action gates
`ai_agent_payment_action` is a recognized action_type that requires accountable signoff regardless of amount. Autonomous agents that initiate transfers cannot consume without a named human signoff bound to the exact action.

## Proof points
- 3,430 automated tests across 129 test files (`npx vitest run`)
- 20 TLA+ safety properties verified (T1–T20, TLC 2.19, 7,857 states, 0 errors); 6 additional EP-IX properties (T21–T26) specified, model run pending
- 85 red team cases cataloged in `docs/conformance/RED_TEAM_CASES.md`
- 32 Alloy facts + 15 assertions verified (Alloy 6.1.0)
- 29 concurrency warfare tests (100-way consumption races)
- Append-only event store with DB-level immutability triggers
- One-time consumption enforced at both application and database level
- Internal security audit: 100/100 self-administered (see `docs/security/AUDIT_METHODOLOGY.md`); third-party engagement planned

## Pilot outputs
- Workflow-specific control architecture
- Policy and signoff configuration (action types, money-destination guards, escalation thresholds)
- Event and evidence package — auditor inspectable
- 30-day success metrics: receipts issued, signoffs requested, signoff response time, would-have-been-blocked counts (observe mode), actually-blocked counts (enforce mode)
- Implementation guide for transition to production
- Results review with the institution's risk and audit teams
