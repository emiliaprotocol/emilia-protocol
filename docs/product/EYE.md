# EMILIA Protocol -- Eye Product Layers

## Overview

Emilia Eye has one implemented public reference layer and two target product layers. The Open layer is inspectable and sufficient for an organization to build and operate its own implementation. Managed and Enterprise describe future, separately scoped service designs. No generally available Eye hosted service, SLA, or customer deployment is operating today.

---

## Open

The Open layer is the specification and reference implementation. It is freely available and sufficient for any organization to build and operate their own Eye deployment.

### What Is Included

| Component | Description |
|---|---|
| Eye specification | The complete architectural specification, object model, status model, API contract, abuse model, and conformance invariants. |
| OSS runtime | Reference implementation of the Eye evaluation engine. Accepts observations, computes advisories, enforces TTLs, manages suppressions. Designed for self-hosted deployment. |
| SDKs | Client libraries for submitting observations and querying advisories. Available for the same languages as the EP SDK set. |
| Conformance test suite | Tests that verify an implementation satisfies the six Eye invariants. Runnable against any deployment. |

### What Is Not Included

Signal definitions beyond a minimal starter set. Observation source integrations. Dashboards. Analytics. Multi-tenant isolation. SLA guarantees.

### License

Same open-source license as the EP protocol specification and reference implementation.

---

## Managed target

No Managed Eye service operates today. This target layer would provide hosted infrastructure, a signal registry, and operational tooling around the Open specification under a separate contract and verified deployment boundary.

### Target capabilities

| Component | Description |
|---|---|
| Signal registry | A curated, versioned registry of signal definitions. Each definition includes the signal_code, expected severity range, required evidence fields, and evaluation rules. New signal definitions are published on a regular cadence. Operators select which signals are active for their deployment. |
| Dashboards | Operational dashboards showing advisory status distribution, observation volume by source, suppression activity, TTL coverage, and status trend lines. Read-only. No entity-level detail exposed in dashboard views. |
| Analytics | Aggregate analytics on signal effectiveness: false-positive rates by signal_code, advisory-to-enforcement correlation, suppression frequency by authority class. Used for signal definition tuning, not for entity scoring. |
| Suppression controls | UI and API for managing suppressions with approval workflows. Supports multi-level suppression approval for critical-severity observations. Audit log export for SIEM integration. |
| Eye-to-EP orchestration | Managed integration between Eye advisories and EP policy resolution. Advisory status is automatically available as a policy input during handshake verification. No custom integration code required. |
| Source management | Registration, authentication, rate limiting, and monitoring for observation sources. Token rotation, source suspension, and per-source analytics. |
| Hosted API | Target operation of the four Eye API endpoints with tenant isolation, a contracted availability objective, and verified regional placement. |

### What Is Not Included

Private deployment infrastructure. Custom signal definitions authored by the operator. Source integrations with the operator's internal systems. Custom governance workflows.

---

## Enterprise target

No Enterprise Eye deployment package is generally available today. This target layer would extend a separately scoped implementation for organizations that need private infrastructure, custom signal sources, or governance integration.

### Target capabilities

| Component | Description |
|---|---|
| Private deployments | Eye infrastructure deployed within the operator's cloud environment or private data center. Observation and advisory data does not leave the operator's network boundary. |
| Source integrations | Pre-built integrations with the operator's internal signal sources: fraud detection systems, identity verification providers, transaction monitoring platforms, regulatory alert feeds, infrastructure monitoring. Custom integration development is available as a professional services engagement. |
| Custom signal packs | Signal definitions authored by or for the operator, reflecting their specific risk model and trust requirements. Custom signal packs are versioned and tested against the conformance suite before deployment. |
| Governance integration | Integration with the operator's governance, risk, and compliance (GRC) tooling. Advisory and suppression events flow to the operator's SIEM, case management, and audit systems. Suppression approval workflows integrate with the operator's existing authority and delegation models. |
| Multi-region deployment | Eye infrastructure deployed across multiple regions with observation routing, advisory consistency guarantees, and region-specific signal configurations. |
| Dedicated support | Named support contact. Incident response SLA. Signal definition consultation. Integration architecture review. |

---

## Layer Boundaries

| Capability | Open reference | Managed target | Enterprise target |
|---|---|---|---|
| Specification and conformance tests | Yes | Yes | Yes |
| OSS runtime | Yes | Yes | Yes |
| SDKs | Yes | Yes | Yes |
| Hosted API with SLA | No | Target | Target |
| Signal registry | Starter set only | Target: curated, versioned | Target: curated + custom |
| Dashboards and analytics | No | Target | Target |
| Suppression controls with workflows | Basic (API only) | Target | Target + GRC integration |
| Eye-to-EP orchestration | Manual integration | Target | Target + custom |
| Source management | Self-managed | Target | Target + custom integrations |
| Private deployment | Self-hosted reference | No | Target |
| Custom signal packs | Self-authored | No | Target |
| Governance integration | No | No | Target |
