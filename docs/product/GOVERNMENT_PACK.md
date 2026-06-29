# Government Pack

The Government Pack productizes EMILIA Protocol for public-sector workflows
where fraud or abuse can happen inside valid sessions.

## First workflows

- `gov.vendor_payment_destination_change` — vendor/supplier payment routing
- `gov.disbursement_release` — treasury or AP disbursement release
- `gov.grant_disbursement` — program/grant/award payment release
- `benefit_bank_account_change` — benefit direct-deposit change
- `benefit_address_change` — address/contact/identity routing changes that can redirect notices or credentials
- `gov.provider_enrollment_change` — provider status, payment address, NPI, or enrollment file changes
- `gov.eligibility_override` — regulated eligibility decision override
- `caseworker_override` — operator override of an automated recommendation or control

## What it contains

- GovGuard precheck adapters for each workflow above
- Class-A policy defaults for high-risk government actions
- GG-1 conformance checks
- procurement evidence packet export
- observe / warn / enforce rollout modes
- signoff patterns and two-person-rule escalation path
- implementation notes for government environments

## First deployment motion

Run the **GovGuard Fire Drill** in observe mode:

1. Send one fraud-prone workflow through a GovGuard adapter.
2. Record what enforce mode would have denied or held for named signoff.
3. Export the evidence packet.
4. Verify representative signed receipts offline.
5. Move one workflow to enforce mode only after the agency trusts the evidence.

The pack is not a fraud detector. It is a pre-execution accountability layer:
before money, provider status, eligibility, or regulated state changes, the
system can prove who authorized the exact action under the exact policy.
