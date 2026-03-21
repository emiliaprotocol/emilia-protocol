# EP Financial Pack

Vertical policy and integration pack for financial services deployments.

## Overview

The EP Financial Pack provides reference policies, evidence templates,
and integration patterns for financial services use cases. It addresses
the trust-enforcement problems specific to payment processing, treasury
operations, vendor management, and regulatory compliance in banking,
insurance, and financial technology organizations.

Financial services fraud follows a consistent pattern: authorized
personnel, valid sessions, legitimate system access, and weak
action-level controls. A treasury analyst redirecting a wire transfer,
a vendor manager changing remittance details without dual authorization,
an exception process that bypasses threshold controls. EP's
handshake-before-action model addresses these threats. The Financial
Pack provides the specific policy configurations and evidence structures
that map EP to financial services operational patterns.

This pack runs on EP Cloud or EP Enterprise. It does not modify the
protocol kernel.

---

## Capabilities

### Beneficiary and Remittance Change Controls

Changes to payment beneficiary details are a primary attack vector in
financial fraud. The Financial Pack provides policies that enforce
verification before these changes take effect:

- **Account detail change handshakes:** Any modification to a
  beneficiary's bank account, routing number, or payment instructions
  requires a verified handshake binding the change to the actor's
  identity, the specific old and new values, and the governing policy
  version.
- **Cooling period enforcement:** Policies can require a configurable
  delay between beneficiary change approval and first payment to the
  new destination. The handshake records the approval timestamp;
  downstream systems enforce the cooling period.
- **Change magnitude awareness:** Policy rules can vary verification
  requirements based on the nature of the change (e.g., domestic
  re-routing vs. international re-routing).
- **Callback verification patterns:** Integration guidance for
  pairing EP handshakes with out-of-band beneficiary confirmation
  (e.g., callback to the beneficiary's registered contact).

**Connection to the kernel:** Beneficiary changes are bound through
the standard handshake mechanism. The `action_type` and
`resource_ref` fields on the handshake identify the specific change.
The binding hash covers the full change context, preventing
modification after initiation.

### Treasury Approval Controls

Treasury operations involve high-value, low-frequency actions that
require structured authorization:

- **Dual authorization:** Treasury actions above a configurable
  threshold require two independent authorized parties to complete
  separate handshakes. Neither party's individual handshake is
  sufficient; both must verify before the action proceeds.
- **Segregation of duties:** Policy rules enforce that the initiator
  and the approver are different individuals with different authority
  credentials.
- **Authority-level requirements:** Treasury policies can require
  specific authority levels (e.g., department head, CFO) for actions
  above defined thresholds.
- **Time-windowed authorization:** Treasury approvals expire within
  a configurable window. An approval granted on Monday cannot be
  used to execute on Friday if the policy requires same-day
  execution.

**Why it matters:** Treasury fraud typically exploits the gap between
having system access and having legitimate authority for a specific
transaction. Dual authorization through EP handshakes closes that gap
with cryptographic binding and immutable evidence.

### Exception and Threshold Policies

Financial operations require structured exception handling. The
Financial Pack provides policy patterns for managing exceptions without
undermining controls:

- **Threshold-based escalation:** Actions are classified by value,
  risk, or counterparty. Each threshold tier maps to a different
  policy with different verification requirements.
- **Exception request handshakes:** Requesting an exception to
  standard policy is itself a handshake-bound action. The exception
  request, justification, and approval are recorded as trust
  evidence.
- **Exception time limits:** Approved exceptions are time-bounded
  and scope-bounded. An exception approved for one transaction
  does not carry over to subsequent transactions.
- **Exception monitoring:** Policy analytics track exception
  frequency, approval rates, and patterns. Anomalous exception
  volumes trigger alerts.

### Dual Signoff Patterns

The Financial Pack provides configurable dual-signoff patterns that
go beyond simple two-party approval:

- **Amount-based escalation matrix:** Define signoff requirements
  as a function of transaction amount. For example:
  - Below $10,000: single authorized operator.
  - $10,000 - $100,000: operator plus supervisor.
  - $100,000 - $1,000,000: operator plus department head.
  - Above $1,000,000: operator plus CFO plus board-designated
    approver.
- **Role-based signoff:** Signoff requirements defined by the
  role relationship between the initiator and the action (e.g.,
  an action involving the initiator's own department requires
  an out-of-department approver).
- **Sequential and parallel signoff:** Configure whether multiple
  approvers must sign off in sequence (each seeing the previous
  approver's decision) or in parallel (independent decisions).
- **Signoff deadlines:** Each signoff request has a configurable
  expiry. If all required signoffs are not completed within the
  window, the action is rejected.

**Connection to the kernel:** Dual signoff is implemented through
the handshake party model. Each required approver is added as a
party with the appropriate role. The handshake does not reach
`verified` status until all required parties have submitted valid
presentations.

### Payment-Action Evidence Exports

Financial regulators and auditors require specific evidence for
payment actions. The Financial Pack provides SOX-aligned export
templates:

- **SOX-ready evidence packages:** Structured exports that document
  the authorization chain for each payment action: who initiated,
  who approved, under what policy, with what evidence, at what time.
- **Control effectiveness documentation:** Exports that demonstrate
  the operating effectiveness of EP controls over a reporting period
  (e.g., all wire transfers above $50,000 required and received dual
  authorization during Q3).
- **Exception documentation:** Exports that itemize all exceptions
  granted during a period, with justifications, approvers, and
  scope.
- **Sampling support:** Random or stratified sampling of payment
  actions for audit testing.

### Wire Transfer Protection Patterns

Wire transfers are irreversible and high-value. The Financial Pack
provides specific protection patterns:

- **Pre-execution handshake:** Every wire transfer above a
  configurable threshold requires a completed handshake before
  the transfer instruction is submitted to the payment network.
- **Beneficiary validation binding:** The handshake binds the
  specific beneficiary details (name, account, routing, bank)
  to the authorization. Any mismatch between the authorized
  details and the submitted transfer triggers rejection.
- **Velocity controls:** Policies can define velocity limits
  (e.g., maximum number of wires per day per operator, maximum
  aggregate value per day). Velocity checks are evaluated as
  policy rules during handshake verification.
- **Unusual pattern detection:** Integration guidance for feeding
  EP policy analytics into fraud detection systems. EP provides
  the structured authorization data; fraud systems provide
  behavioral analysis.

### Vendor Management Controls

Vendor onboarding and payment detail changes are trust-sensitive
operations:

- **Vendor onboarding handshake:** Adding a new vendor to the
  payment system requires a handshake binding the vendor details
  to the onboarding operator's identity and the approval
  authority.
- **Vendor detail change controls:** Changes to an existing
  vendor's payment details follow the same beneficiary-change
  control patterns, with additional verification requirements
  configurable per vendor risk tier.
- **Vendor deactivation controls:** Deactivating a vendor
  requires a handshake to prevent unauthorized removal (which
  could mask fraudulent re-addition with different details).
- **Vendor audit trail:** Complete event history for each vendor
  entity, from onboarding through every detail change.

### Reference Policy Configurations

Pre-built policy configurations for common financial scenarios:

- **Wire transfer authorization:** Threshold-based dual signoff
  with beneficiary binding and velocity controls.
- **ACH batch approval:** Batch authorization with per-item
  binding for ACH payment files.
- **Vendor payment change:** Dual authorization for vendor
  payment detail modifications with cooling period.
- **Treasury investment authorization:** Multi-level approval
  for investment transactions with counterparty binding.
- **Account opening/closing:** Structured authorization for
  account lifecycle events.

These configurations are starting points. Organizations adapt them
to their specific risk appetite and regulatory requirements.

---

## Relationship to the Protocol Kernel

The Financial Pack does not modify EP's protocol kernel:

- Policies are standard EP policies resolved by `resolvePolicy()`.
- Handshakes follow the standard lifecycle with standard replay
  resistance.
- Events are written to the same append-only, trigger-protected
  tables.
- Dual signoff is implemented through the standard multi-party
  handshake model, not through a separate mechanism.

The Financial Pack's value is in pre-built configurations, escalation
patterns, and evidence templates that reduce time-to-value for
financial services organizations adopting EP.

---

## Deployment

The Financial Pack can be deployed on:

- **EP Cloud:** For financial technology companies and organizations
  whose compliance posture allows hosted deployment.
- **EP Enterprise:** For banks, insurers, and regulated financial
  institutions requiring private infrastructure, data residency,
  and custom trust-root controls.

Most regulated financial institutions will deploy on EP Enterprise
with the Financial Pack layered on top.
