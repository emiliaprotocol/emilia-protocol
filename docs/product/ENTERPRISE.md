# EP Enterprise

Hardened deployment and governance layer for EMILIA Protocol.

## Overview

EP Enterprise extends EP Cloud for organizations that require private
infrastructure, regulatory-grade controls, and advanced governance. It
provides the same protocol kernel guarantees -- `protocolWrite()` as the
single choke point, append-only event logging, policy-hash binding, and
replay resistance -- deployed inside the customer's own infrastructure
boundary.

EP Enterprise exists because many organizations that need trust-before-action
enforcement operate under constraints that hosted multi-tenant infrastructure
cannot satisfy: data-residency mandates, air-gapped networks, custom
certificate authorities, or compliance regimes that require physical
infrastructure control.

---

## Capabilities

### Private Cloud / VPC Deployment

EP Enterprise deploys into customer-controlled infrastructure:

- **VPC-native:** Runs inside the customer's AWS VPC, Azure VNet, or GCP
  VPC. No trust-critical data leaves the customer's network boundary.
- **Air-gap capable:** Supports fully disconnected environments where
  internet access is restricted or prohibited.
- **Infrastructure-as-code:** Deployment is automated via Terraform, Helm,
  or equivalent tooling. Reproducible and auditable.
- **Upgrade path:** Managed upgrade lifecycle with release notes, staging
  validation, and rollback support.

**Why it matters:** Trust-critical infrastructure must sit where the
organization's compliance and security posture requires it. EP Enterprise
removes the constraint of hosted deployment.

### Data Residency

Event data, policy definitions, and handshake records can be pinned to
specific geographic regions:

- **Region-pinned storage:** All EP data -- `protocol_events`,
  `handshake_events`, policies, bindings -- stored in the designated region.
- **No cross-region replication by default:** Data does not leave the
  designated region unless explicitly configured for multi-region.
- **Residency attestation:** EP provides configuration artifacts that
  document where data is stored, for inclusion in compliance packages.

**Connection to the kernel:** The append-only event tables
(`protocol_events`, `handshake_events`) are the primary data subject for
residency controls. Their trigger-enforced immutability means residency
is a storage-layer concern, not an application-layer concern.

### SSO / SCIM Integration

EP Enterprise integrates with enterprise identity infrastructure:

- **SSO:** SAML 2.0 and OIDC support for operator authentication to the
  EP management plane.
- **SCIM:** Automated user and group provisioning from the organization's
  identity provider. User lifecycle (create, update, deactivate) is
  managed centrally.
- **Session management:** Configurable session duration, idle timeout,
  and forced re-authentication for sensitive operations.

### Advanced RBAC

Fine-grained permission model for EP operations:

- **Role hierarchy:** Predefined roles (viewer, operator, policy author,
  policy approver, administrator) with clear permission boundaries.
- **Custom roles:** Organizations can define custom roles with specific
  permission sets.
- **Resource-scoped permissions:** Permissions can be scoped to specific
  tenants, environments, policy namespaces, or action types.
- **Separation of duties:** Policy authorship and policy approval can be
  assigned to different roles, enforcing four-eyes principle on policy
  changes.
- **Permission audit log:** All permission grants, revocations, and role
  changes are logged.

**Why it matters:** In regulated environments, the ability to demonstrate
who can do what within the trust-control system is itself an audit
requirement.

### Delegated Administration

Large organizations can delegate administration to business units:

- **Organizational hierarchy:** Define business units, teams, or
  departments as administrative scopes.
- **Scoped administrators:** Delegated admins manage policies, users, and
  configuration within their scope. They cannot affect other scopes.
- **Central oversight:** A global administrator retains visibility and
  override capability across all scopes.
- **Delegation audit trail:** All delegated administrative actions are
  logged with the acting administrator's identity.

### Multi-Region Options

For organizations requiring geographic redundancy:

- **Active-passive:** Primary region handles all verification traffic.
  Secondary region receives replicated data and can be promoted on
  failure. RPO and RTO are documented per configuration.
- **Path to active-active:** Architectural guidance and configuration
  support for multi-region active-active deployment. This mode requires
  careful handling of nonce uniqueness and one-time consumption semantics
  across regions.
- **Region failover:** Automated or manual failover procedures with
  documented recovery steps.

**Connection to the kernel:** One-time consumption (`consumed_at IS NULL`
filter) is the most sensitive operation in a multi-region context. EP
Enterprise documents the consistency requirements and provides
configuration patterns that preserve this guarantee.

### Enterprise Evidence Retention

Configurable retention for trust evidence:

- **Retention windows:** Define how long event data, handshake records,
  and policy versions are retained. Configurable per data type, per
  tenant, or per environment.
- **Legal hold:** Place a hold on specific records or time ranges to
  prevent scheduled deletion. Legal holds override retention policies.
- **Retention policy audit:** Changes to retention configuration are
  logged. The retention policy itself is versioned.
- **Tiered storage:** Older evidence can be moved to cold storage while
  remaining queryable for audit and compliance purposes.

### Regulator / Auditor Artifacts

Pre-packaged evidence exports for external review:

- **Evidence bundles:** Export a structured package containing handshake
  records, policy versions (with hashes), event sequences, and actor
  identity chains for a defined scope (time range, action type, entity).
- **Chain-of-custody documentation:** Each export includes metadata
  documenting when it was generated, by whom, and what query produced it.
- **Format compatibility:** Exports in JSON, CSV, and PDF formats to
  accommodate different auditor tooling.
- **Scheduled exports:** Configure recurring exports for periodic
  regulatory submissions.

### Incident and Forensics Tooling

When something goes wrong, EP Enterprise provides reconstruction tools:

- **Event reconstruction:** Given an entity, action, or time range,
  reconstruct the full sequence of trust-changing events. Follows the
  `parent_event_hash` chain to build a complete causal history.
- **Timeline views:** Visual chronological display of handshake
  lifecycle events for a specific action or entity.
- **Anomaly detection:** Surface handshakes that were rejected,
  expired, or exhibited unusual patterns (e.g., repeated failed
  verifications from the same actor).
- **Correlation:** Link related events across aggregate types
  (e.g., a receipt that was preceded by a handshake and followed by
  a dispute).

**Connection to the kernel:** Forensics operates on the append-only
event tables. Because these tables cannot be updated or deleted
(trigger-enforced), the forensic record is guaranteed complete.

### Custom Issuer and Trust-Root Controls

EP Enterprise supports customer-managed trust roots:

- **Custom issuers:** Organizations can register their own issuers in
  the authority registry. `resolveAuthority()` will resolve against
  these custom issuers during handshake verification.
- **Trust-root pinning:** Restrict which issuers are trusted for
  specific action types or policy namespaces.
- **Certificate lifecycle:** Manage issuer certificate rotation with
  overlap windows to prevent verification gaps.
- **Issuer audit:** All issuer registrations, rotations, and
  decommissions are logged.

### Support and Review Packages

EP Enterprise includes structured support:

- **Dedicated support:** Named support contacts with defined response
  times based on severity.
- **Architecture review:** Periodic review of the customer's EP
  deployment, policy configuration, and integration patterns.
- **Policy review:** Expert review of policy configurations for
  correctness, coverage, and alignment with organizational risk
  posture.
- **Upgrade planning:** Coordinated planning for EP version upgrades,
  including staging validation and rollback procedures.

---

## Relationship to EP Cloud

EP Enterprise is not a replacement for EP Cloud. It is the deployment
model for organizations whose constraints prevent hosted multi-tenant
operation.

- The protocol kernel is identical. `protocolWrite()`, policy resolution,
  replay resistance, and append-only event logging operate the same way.
- EP Cloud features (policy simulation, rollout controls, analytics,
  observability) are available in EP Enterprise deployments.
- EP Enterprise adds: private infrastructure, data residency, SSO/SCIM,
  advanced RBAC, delegated administration, multi-region, custom trust
  roots, and enterprise-grade evidence management.

---

## Intended Use

EP Enterprise is appropriate for organizations operating under regulatory
mandates (financial services, government, healthcare), organizations with
data-residency requirements, or organizations whose security posture
requires trust infrastructure inside their own network boundary.
