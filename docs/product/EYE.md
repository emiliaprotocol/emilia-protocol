# EMILIA Protocol -- Eye Product Layers

## Overview

Emilia Eye is delivered in three layers: Open, Managed, and Enterprise. Each layer builds on the one below it. The Open layer is sufficient for implementation. The Managed and Enterprise layers reduce operational burden and add capabilities that require hosted infrastructure.

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

## Managed

The Managed layer is a hosted service operated by Emilia that provides the infrastructure, signal registry, and operational tooling around the Open specification.

### What Is Included

| Component | Description |
|---|---|
| Signal registry | A curated, versioned registry of signal definitions. Each definition includes the signal_code, expected severity range, required evidence fields, and evaluation rules. New signal definitions are published on a regular cadence. Operators select which signals are active for their deployment. |
| Dashboards | Operational dashboards showing advisory status distribution, observation volume by source, suppression activity, TTL coverage, and status trend lines. Read-only. No entity-level detail exposed in dashboard views. |
| Analytics | Aggregate analytics on signal effectiveness: false-positive rates by signal_code, advisory-to-enforcement correlation, suppression frequency by authority class. Used for signal definition tuning, not for entity scoring. |
| Suppression controls | UI and API for managing suppressions with approval workflows. Supports multi-level suppression approval for critical-severity observations. Audit log export for SIEM integration. |
| Eye-to-EP orchestration | Managed integration between Eye advisories and EP policy resolution. Advisory status is automatically available as a policy input during handshake verification. No custom integration code required. |
| Source management | Registration, authentication, rate limiting, and monitoring for observation sources. Token rotation, source suspension, and per-source analytics. |
| Hosted API | The four Eye API endpoints operated as a managed service with tenant isolation, availability SLA, and geographic deployment options. |

### What Is Not Included

Private deployment infrastructure. Custom signal definitions authored by the operator. Source integrations with the operator's internal systems. Custom governance workflows.

---

## Enterprise

The Enterprise layer extends Managed with capabilities required by organizations that need private infrastructure, custom signal sources, or governance integration.

### What Is Included

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

| Capability | Open | Managed | Enterprise |
|---|---|---|---|
| Specification and conformance tests | Yes | Yes | Yes |
| OSS runtime | Yes | Yes | Yes |
| SDKs | Yes | Yes | Yes |
| Hosted API with SLA | No | Yes | Yes |
| Signal registry | Starter set only | Curated, versioned | Curated + custom |
| Dashboards and analytics | No | Yes | Yes |
| Suppression controls with workflows | Basic (API only) | Yes | Yes + GRC integration |
| Eye-to-EP orchestration | Manual integration | Managed | Managed + custom |
| Source management | Self-managed | Managed | Managed + custom integrations |
| Private deployment | Self-hosted | No | Yes |
| Custom signal packs | Self-authored | No | Yes |
| Governance integration | No | No | Yes |
