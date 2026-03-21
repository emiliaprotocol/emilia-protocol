# EP Government Pack

Vertical policy and integration pack for government deployments.

## Overview

The EP Government Pack provides reference policies, integration patterns, and
evidence templates purpose-built for government use cases. It addresses the
specific trust-enforcement problems that arise in benefits administration,
case management, payment processing, and regulatory compliance within
government agencies.

Government systems face a distinct threat model: authorized operators
performing unauthorized actions within valid sessions. A caseworker
redirecting a benefit payment, a supervisor overriding a determination
without documented authority, a batch process applying changes without
individual accountability. EP's handshake-before-action model addresses
these threats directly. The Government Pack provides the specific policy
configurations and evidence structures that map EP to government
operational patterns.

This pack runs on EP Cloud or EP Enterprise. It does not modify the
protocol kernel. It provides configuration and tooling that sits above
the kernel.

---

## Capabilities

### Benefits and Payment Redirect Controls

Government benefit payments are a high-value fraud target. The Government
Pack provides policies that enforce trust verification before payment
destination changes:

- **Address and account change handshakes:** Any modification to a
  beneficiary's payment destination (bank account, mailing address,
  direct deposit routing) requires a verified handshake.
- **Policy-bound verification:** The handshake binds the specific
  change (old destination, new destination) to the actor's identity,
  authority chain, and the governing policy version with hash.
- **Replay resistance:** Each payment redirect is bound to a unique
  nonce with expiry. A captured authorization cannot be replayed
  against a different beneficiary or a different destination.
- **Evidence trail:** The handshake record, including all presentations
  and the verification result, persists as auditable evidence.

**Why it matters:** Payment redirect fraud in government benefits
programs results in billions of dollars in annual losses. EP does not
prevent all fraud, but it ensures that every payment redirect is
individually authorized, policy-bound, and evidenced.

### Operator Override Constraints

Government systems frequently require operator overrides for exceptional
cases. The Government Pack structures these overrides:

- **Supervisor escalation policies:** Overrides above a defined risk
  threshold require a supervisor-level handshake. The supervisor's
  identity and authority are bound to the override action.
- **Override justification binding:** The operator must provide a
  structured justification that is included in the handshake payload.
  The justification becomes part of the immutable event record.
- **Override rate monitoring:** Policy analytics track override
  frequency per operator, per action type. Anomalous override
  patterns surface through EP's observability layer.
- **Time-bounded overrides:** Override authorizations expire. An
  override approved for one case cannot be reused for another.

**Connection to the kernel:** Override constraints use the standard
handshake mechanism. The supervisor's signoff is a presentation added
to the handshake by a party with the `verifier` or `delegate` role.
The policy defines what authority level is required.

### Delegated Case-Action Controls

Government case management involves multiple actors performing actions
on shared cases. The Government Pack provides delegation controls:

- **Delegation chain policies:** Define who can delegate case actions
  to whom, under what constraints. Delegation is itself a
  handshake-bound action.
- **Delegated authority limits:** A delegated actor inherits only the
  specific authorities granted by the delegation, not the delegator's
  full authority.
- **Delegation expiry:** Delegations are time-bounded. Expired
  delegations are rejected at verification time.
- **Delegation evidence:** The delegation chain is recorded in the
  handshake record. Auditors can trace the authority path from the
  acting operator back through each delegation to the original
  authority holder.

### Audit Evidence Templates

Government audits (Inspector General, GAO, congressional oversight)
require specific evidence formats. The Government Pack provides
templates that map EP's event data to these requirements:

- **IG-ready evidence packages:** Pre-structured exports that include
  handshake records, policy versions, actor identity chains, and
  event timelines in formats aligned with IG investigation standards.
- **GAO-ready audit trails:** Exports structured for GAO audit
  methodology, including control effectiveness evidence and
  transaction-level detail.
- **Finding response templates:** When an audit finding identifies a
  control gap, the Government Pack provides templates for
  demonstrating remediation through EP policy changes.
- **Sampling support:** Export random or stratified samples of
  handshake records for statistical audit methods.

**Why it matters:** The value of EP's trust evidence is reduced if it
cannot be presented in the formats auditors and investigators expect.
Templates bridge EP's data model and the audit community's expectations.

### Approval Ownership Policies

In government workflows, specific individuals must own specific
approvals. The Government Pack enforces this:

- **Named-owner policies:** High-risk actions require signoff from a
  specific named individual (or a member of a named group), not just
  anyone with a role.
- **Quorum policies:** Certain actions require signoff from multiple
  named owners (e.g., two of three designated approvers).
- **Approval rotation:** Define rotation schedules for approval
  ownership to prevent single-point-of-failure and distribute
  accountability.
- **Vacancy handling:** If a named approver is unavailable, policies
  define escalation paths with documented authority transfer.

### Reference Policy Configurations

The Government Pack includes pre-built policy configurations for common
government scenarios:

- **Benefit payment change:** Handshake required for any change to
  payment routing, with identity verification level based on change
  magnitude.
- **Case determination override:** Supervisor handshake required for
  determinations that override automated eligibility assessments.
- **Batch processing controls:** Batch operations that affect multiple
  beneficiaries require individual handshakes per affected record, or
  a batch-authorization handshake with explicit scope binding.
- **Inter-agency data sharing:** Handshake required before sharing
  case data with another agency, binding the sharing action to the
  data-sharing agreement and the receiving agency's identity.

These are starting points. Organizations customize them for their
specific operational context.

### Integration Patterns with Government Identity Systems

Government agencies use specific identity infrastructure. The Government
Pack provides integration guidance and adapters for:

- **PIV / CAC card integration:** Map PIV/CAC certificate-based
  identity to EP's actor identity model for handshake initiation.
- **Login.gov / MAX.gov:** Integration patterns for federal
  authentication services.
- **Agency-specific IdPs:** Guidance for integrating agency-managed
  identity providers with EP's authority resolution.
- **Identity assurance level mapping:** Map NIST SP 800-63 identity
  assurance levels to EP policy requirements (e.g., IAL2 required
  for payment changes above a threshold).

**Connection to the kernel:** Identity integration feeds into
`resolveAuthority()`. The Government Pack provides the issuer
configurations and authority registry entries that allow government
identity credentials to be resolved during handshake verification.

### Compliance Mapping

The Government Pack documents how EP's controls map to federal
compliance frameworks:

- **FISMA:** Mapping of EP capabilities to NIST SP 800-53 control
  families (AC, AU, IA, SC). Documentation of how EP satisfies or
  supports specific controls.
- **FedRAMP considerations:** Guidance for deploying EP in FedRAMP-
  authorized environments. Shared responsibility documentation.
- **NIST Cybersecurity Framework:** Mapping of EP capabilities to
  CSF functions (Identify, Protect, Detect, Respond, Recover).
- **OMB mandates:** Mapping to relevant OMB memoranda on identity,
  access management, and zero trust architecture.

These mappings do not constitute certification. They provide the
documentation foundation for an agency's own compliance assessment.

---

## Relationship to the Protocol Kernel

The Government Pack does not modify EP's protocol kernel. It operates
entirely in the configuration and tooling layer:

- Policies are standard EP policies loaded by `resolvePolicy()`.
- Handshakes follow the standard lifecycle (initiate, present, verify).
- Events are written to the same append-only tables.
- Replay resistance mechanisms are unchanged.

The Government Pack's value is in pre-built configurations, integration
patterns, and evidence templates that reduce the time from EP adoption
to operational trust enforcement in government environments.

---

## Deployment

The Government Pack can be deployed on:

- **EP Cloud:** For agencies whose data classification and compliance
  posture allow hosted infrastructure.
- **EP Enterprise:** For agencies requiring private cloud, VPC, or
  air-gapped deployment with data residency controls.

The pack is the same in both cases. The deployment model is chosen
independently based on infrastructure requirements.
