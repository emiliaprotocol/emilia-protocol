# EP for Government Fraud Prevention

Government fraud often succeeds inside authorized systems, through
authenticated users and approved-looking workflows. The missing control is not
simple identity verification. It is action-level authorization: proving that a
specific actor, under a specific authority chain, can perform a specific
high-risk action under a specific policy, exactly once.

EMILIA GovGuard provides that control layer. It sits downstream of identity and
upstream of execution, binding high-risk government actions to policy,
authority, transaction context, replay resistance, and durable event
traceability before they take effect.

## Positioning

**Pre-payment control for government fraud.**

Run a GovGuard fire drill against one fraud-prone workflow and see whether the
agency can prove who would have authorized the dangerous action before money or
regulated state moved.

## Best-fit use cases

- vendor payment-destination changes
- disbursement releases
- grant disbursements
- benefit direct-deposit changes
- benefit address/contact/identity routing changes
- provider enrollment and payment-address changes
- eligibility overrides
- caseworker/operator overrides
- AI-assisted service workflows

## Why EP fits

EP gives agencies a protocol-grade substrate for:

- actor identity from authenticated context
- organization binding from the API key, not request body
- policy-bound approvals
- Class-A/passkey signoff for high-risk actions
- exact transaction and execution-field binding
- replay resistance and one-time receipt consumption
- observe-mode evidence export before enforcement
- procurement-grade evidence packets

## Best first pilot

Start with one high-risk workflow:

- vendor payment destination change
- disbursement release
- benefit routing change
- provider enrollment change
- eligibility/caseworker override

Success is not "the tool found fraud." Success is:

> The agency can point to a high-risk action and prove whether it would have
> been denied, held for named approval, or allowed, under the active policy.

## What evidence agencies get

- decision record
- policy hash and rule reason
- action hash
- execution-binding hash
- signoff trace if required
- GG-1 conformance status
- offline verifier command
- reconstruction-ready export for auditors, controllers, Inspectors General,
  or insurers
