# EP Cloud

Managed trust-control plane for EMILIA Protocol.

## Overview

EP Cloud is the hosted operational layer for EP. It provides the infrastructure
required to run EP handshakes, policy enforcement, and audit logging without
self-managing the trust substrate. Organizations deploy policy, connect their
applications, and EP Cloud handles verification, event persistence, and
observability.

EP Cloud does not replace the protocol kernel. It hosts it. Every handshake
still flows through `protocolWrite()`, every binding is still nonce-bound and
one-time-consumed, and every event is still append-only. EP Cloud adds the
operational surface: management UIs, policy tooling, multi-tenant isolation,
and reliability guarantees.

---

## Capabilities

### Hosted Verification

EP Cloud runs the full handshake lifecycle on managed infrastructure:

- Handshake initiation, presentation, binding, and verification.
- Nonce generation, expiry enforcement, binding-hash computation, and
  one-time consumption -- all executed server-side.
- Applications call the EP Cloud API instead of running the verification
  pipeline locally.
- Fail-closed semantics preserved: if EP Cloud cannot verify, the action
  does not proceed.

**Why it matters:** Organizations get the full replay-resistance and
policy-binding guarantees of EP without operating the verification
infrastructure themselves.

### Managed Policy Registry

Policies are the rules that govern which handshakes succeed and which are
rejected. EP Cloud provides a versioned, managed registry for these policies.

- **Version control:** Every policy change creates a new version. Old versions
  remain immutable and referenceable. The `policy_hash` mechanism described in
  the architecture overview operates against these stored versions.
- **Schema validation:** Policies are validated at write time against the EP
  policy schema. Malformed policies are rejected before they can affect
  verification.
- **Metadata and tagging:** Policies can be tagged by domain, environment,
  risk class, or custom dimensions for organizational navigation.

### Policy Simulation

Before deploying a policy change, operators can simulate its effect against
historical handshake data.

- **Replay mode:** Re-run past handshakes against a candidate policy version.
  See which would have been accepted, rejected, or changed outcome.
- **Diff reports:** Compare current-policy outcomes against candidate-policy
  outcomes. Surface the delta before committing.
- **Dry-run API:** Submit a handshake request in simulation mode. Returns the
  verification result without consuming the binding or writing events.

**Why it matters:** Policy changes in trust-critical systems carry operational
risk. Simulation reduces the blast radius of misconfigured rules.

### Rollout Controls

Policy deployment supports graduated rollout:

- **Canary deployment:** Route a small percentage of handshakes to the new
  policy version. Monitor outcomes before full rollout.
- **Percentage-based rollout:** Increase the share of traffic served by the
  new policy version in configurable increments.
- **Instant rollback:** Revert to the previous policy version without
  redeployment. Rollback is a pointer change, not a data migration.
- **Rollout observability:** Real-time comparison of accept/reject rates
  between the current and candidate policy versions during rollout.

### Tenant Management

EP Cloud is multi-tenant by design.

- **Tenant isolation:** Each tenant's handshakes, policies, events, and
  configuration are isolated. No cross-tenant data leakage.
- **Tenant provisioning:** API and UI for creating, configuring, and
  decommissioning tenants.
- **Tenant-scoped API keys:** Each tenant authenticates with its own
  credentials. Keys are scoped to tenant boundaries.
- **Quota and rate limiting:** Per-tenant rate limits prevent noisy-neighbor
  effects.

### Environment Separation

Each tenant can maintain multiple environments:

- **dev / staging / production:** Separate policy registries, event stores,
  and configuration per environment.
- **Promotion workflow:** Promote a policy from dev to staging to production
  with an auditable trail.
- **Environment-scoped API endpoints:** Applications connect to the
  environment-specific endpoint. No risk of dev traffic hitting production
  verification.

### Event Explorer

All protocol events and handshake events written by EP are searchable and
filterable through the Event Explorer.

- **Full-text and structured search:** Search by actor, action type, resource
  reference, policy ID, time range, or outcome.
- **Audit trail reconstruction:** Given an action or entity, reconstruct the
  full sequence of trust-changing events in chronological order.
- **Event detail view:** Inspect the full event payload, including
  `payload_hash`, `parent_event_hash`, `actor_authority_id`, and
  `idempotency_key`.
- **Export:** Export filtered event sets for external audit or compliance
  tooling.

**Connection to the kernel:** The Event Explorer reads from the same
`protocol_events` and `handshake_events` tables described in the architecture
overview. The append-only, trigger-protected nature of these tables guarantees
that the explorer shows a complete and tamper-evident record.

### Hosted Accountable Signoff

Accountable Signoff is EP's mechanism for requiring a named human to attest to
a high-risk action before it executes. EP Cloud manages the orchestration:

- **Challenge delivery:** Deliver signoff challenges to the designated
  accountable party via configured channels (email, push, webhook, SMS).
- **Attestation collection:** Collect the accountable party's response,
  bind it to the handshake as a presentation, and advance the handshake
  lifecycle.
- **Timeout and escalation:** If the accountable party does not respond
  within the configured window, escalate or reject per policy.
- **Attestation evidence:** The signed attestation is stored as part of
  the handshake record, creating durable evidence of who approved what.

### Notification and Challenge Delivery

EP Cloud provides pluggable delivery channels for signoff challenges,
policy alerts, and operational notifications:

- Email, SMS, push notification, and webhook channels.
- Per-policy channel configuration (e.g., wire transfers require SMS;
  routine approvals use email).
- Delivery status tracking and retry logic.
- Channel fallback chains (try push, fall back to SMS).

### Policy Analytics

Operational visibility into how policies behave in production:

- **Policy fire rates:** Which policies are triggered, how often, and by
  which action types.
- **Deny rates:** What fraction of handshakes are rejected per policy,
  per action type, per time window.
- **Latency distribution:** Verification latency percentiles (p50, p95, p99)
  per policy.
- **Trend analysis:** Detect drift in policy behavior over time (e.g., a
  policy that suddenly rejects 3x more than baseline).

### Observability

EP Cloud exposes structured telemetry for operational monitoring:

- **Metrics:** Handshake volume, verification latency, error rates, policy
  evaluation duration, event write latency.
- **Alerts:** Configurable alert rules on any metric (e.g., alert if p99
  verification latency exceeds 500ms, or if deny rate spikes).
- **Dashboards:** Pre-built dashboards for trust operations: handshake
  health, policy performance, event throughput, tenant utilization.
- **Integration:** Metrics export to Prometheus, Datadog, or OpenTelemetry
  collectors. Log export to customer SIEM.

### SLA and Reliability

EP Cloud commits to operational guarantees appropriate for trust-critical
infrastructure:

- **Availability target:** 99.95% uptime for the verification API.
- **Durability target:** Event data is replicated and durable. No verified
  handshake event is lost.
- **Latency target:** p99 verification latency under 500ms for standard
  policy complexity.
- **Recovery time objective (RTO):** Restoration of service within defined
  windows after infrastructure failure.
- **Incident communication:** Status page, incident notifications, and
  post-incident reports.

---

## Relationship to the Protocol Kernel

EP Cloud does not modify the protocol. It hosts it.

- `protocolWrite()` remains the single choke point for all trust-changing
  writes.
- Policy resolution still follows the `resolvePolicy()` chain with hash
  verification at binding time.
- Replay resistance (nonce, expiry, binding hash, one-time consumption,
  idempotency key) operates identically.
- Append-only event tables with trigger-enforced immutability are the
  underlying storage layer.

EP Cloud adds operational surface -- management, simulation, observability,
delivery -- on top of the kernel's guarantees. It does not weaken or bypass
them.

---

## Intended Use

EP Cloud is appropriate for organizations that want EP's trust-enforcement
guarantees without operating the trust infrastructure. It is the default
deployment model for teams adopting EP for the first time, and it serves as
the control plane even when verification is partially distributed to edge
locations.

Organizations with data-residency, air-gap, or regulatory constraints that
prevent hosted deployment should evaluate EP Enterprise.
