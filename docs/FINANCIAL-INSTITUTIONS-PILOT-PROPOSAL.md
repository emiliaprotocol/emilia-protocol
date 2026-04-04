# Financial Institutions Pilot Proposal

## Proposal title
EP for beneficiary changes, payout controls, treasury approvals, and other high-risk financial workflows

## Executive summary
Many of the most expensive failures in finance happen inside approved-looking workflows. EP strengthens the final mile of authorization by binding actor identity, authority, exact transaction context, policy version and hash, replay resistance, and one-time consumption before a high-risk financial action executes.

## Recommended pilot
Choose one workflow:
- beneficiary change
- payout destination change
- vendor remittance update
- treasury release approval

## What the pilot proves
- exact transaction binding
- replay-resistant authorization
- policy-bound approvals
- better audit evidence
- optional Accountable Signoff for higher-risk thresholds

## Capabilities now implemented

### Dual signoff for treasury operations
Two authorized signers must independently attest before a high-value transaction executes. Each attestation is cryptographically bound to the exact transaction details. This is no longer a design-stage feature -- dual signoff is implemented and tested end to end.

### SOX-ready evidence export
`/api/cloud/audit/export` generates compliance packages containing complete event timelines, policy snapshots, binding material, and verification results. Evidence packages are ready for auditor consumption without manual assembly.

### Amount-based escalation
The policy model supports threshold-based escalation matrices. For example, transactions above $50K can require dual signoff, while transactions above $1M can require out-of-band verification. Thresholds and escalation paths are configurable per workflow.

### Wire transfer protection patterns
The Financial Reference Pack includes pre-built policy configurations for the highest-risk wire transfer scenarios: beneficiary changes, remittance changes, and payout destination changes. These patterns are documented and ready to deploy.

## Proof points
- 3,277 automated tests across 125 files, 20 TLA+ safety properties machine-verified (TLC 2.19, 7,857 states, 0 errors), 116 red team cases documented and remediated
- 29 concurrency warfare tests (100-way consumption races)
- Append-only event store with DB-level immutability triggers
- One-time consumption enforced at both application and database level

## Pilot outputs
- workflow-specific control architecture
- policy and signoff configuration
- event and evidence package
- implementation guide
- results review
