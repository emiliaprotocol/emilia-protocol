# EP Regulatory Control Mapping

This document maps EMILIA Protocol mechanisms to established regulatory and compliance frameworks. Each mapping references the specific EP enforcement mechanism and code module that satisfies the control requirement.

---

## NIST Cybersecurity Framework (CSF) 2.0

| Function | Category | EP Mapping | Code Reference |
|---|---|---|---|
| **Govern** | GV.PO -- Policy | Policy publication and versioning. Policies define required claims, assurance levels, and binding requirements. Hash-pinned at handshake initiation. | `lib/handshake/policy.js` (`resolvePolicy()`), `handshake_policies` table |
| **Govern** | GV.RM -- Risk Management | Trust-root management via authority registry. Issuers are registered, versioned, and subject to revocation. No self-asserted trust in production. | `authorities` table, `lib/handshake/present.js` (authority resolution pipeline) |
| **Govern** | GV.SC -- Supply Chain | Delegation chain management with explicit scope and expiry. Third-party actions constrained by delegated authority bounds. | `lib/handshake/bind.js` (`checkDelegation()`), `lib/handshake/create.js` (delegated mode) |
| **Identify** | ID.AM -- Asset Management | Entity registry with unique references. Every actor in the system has a registered identity resolved from authentication, not request payloads. | `lib/protocol-write.js` (`resolveAuthority()`), Invariant 2 |
| **Identify** | ID.RA -- Risk Assessment | Authority resolution with status tracking. Each authority has explicit validity states: valid, revoked, expired, not-yet-valid. | `lib/handshake/present.js` (`_handleAddPresentation()`), `lib/handshake/invariants.js` (`checkIssuerTrusted()`, `checkAuthorityNotRevoked()`) |
| **Protect** | PR.AA -- Identity Management and Access Control | Actor-party binding enforcement. Authenticated entity must match party `entity_ref`. Role spoofing detected and rejected at presentation time. | `lib/handshake/present.js` (ROLE_SPOOFING), `lib/handshake/create.js` (INITIATOR_BINDING_VIOLATION) |
| **Protect** | PR.DS -- Data Security | Transaction binding via canonical binding hash (SHA-256 over all action context fields). Replay resistance via nonce + expiry + one-time consumption. | `lib/handshake/invariants.js` (CANONICAL_BINDING_FIELDS), `lib/handshake/bind.js`, `lib/handshake/verify.js` |
| **Protect** | PR.PS -- Platform Security | Write-path enforcement: runtime proxy (`getGuardedClient()`), CI import guard, CI pattern guard. Trust tables cannot be written outside `protocolWrite()`. | `lib/write-guard.js`, `scripts/check-write-discipline.js`, `scripts/check-protocol-discipline.js` |
| **Detect** | DE.CM -- Continuous Monitoring | Protocol event stream provides real-time visibility into all trust-changing transitions. Handshake events provide lifecycle-level monitoring. | `lib/protocol-write.js` (`appendProtocolEvent()`), `lib/handshake/events.js` |
| **Detect** | DE.AE -- Adverse Event Analysis | Structured rejection reason codes (20+ distinct codes) enable anomaly detection from protocol events. Rejection patterns (repeated `ROLE_SPOOFING`, `delegation_out_of_scope`, `binding_already_consumed`) signal potential attack activity. | `lib/handshake/verify.js` (reason code generation), `lib/handshake/errors.js` |
| **Respond** | RS.AN -- Analysis | Dispute mechanism with structured lifecycle (filed, responded, resolved, appealed, appeal_resolved, withdrawn). Trust reports for abuse/fraud reporting. | `disputes` table, `trust_reports` table, `lib/protocol-write.js` (dispute command handlers) |
| **Respond** | RS.MI -- Mitigation | Revocation of handshakes, commits, and authorities. Revoked issuers immediately affect all future handshake verifications. | `lib/handshake/verify.js` (revocation checking), authority status management |
| **Recover** | RC.RP -- Recovery Planning | Full event reconstruction from append-only logs. `protocol_events` and `handshake_events` provide complete state history. `scripts/replay-protocol.js` supports forensic replay. | `protocol_events` table, `handshake_events` table, `scripts/replay-protocol.js` |
| **Recover** | RC.CO -- Communication | Structured event exports with actor attribution, timestamps, and cryptographic binding material for incident communication and regulatory reporting. | `lib/protocol-write.js` (`buildProtocolEvent()`), event export capabilities |

---

## NIST SP 800-53 Rev. 5 -- Selected Controls

| Control ID | Control Name | EP Mapping | Enforcement |
|---|---|---|---|
| **AC-2** | Account Management | Entity registry with authenticated identity resolution. Actor identity derived from auth middleware, never from request body (Invariant 2). | `lib/protocol-write.js` (`resolveAuthority()`), handshake actor-party binding |
| **AC-3** | Access Enforcement | Pre-action handshake verification. Actions require a verified, policy-bound, unexpired, unconsumed handshake binding. `protocolWrite()` is the single enforcement choke point. | `lib/protocol-write.js` (`protocolWrite()`), `lib/handshake/verify.js` |
| **AC-6** | Least Privilege | Policy-scoped authorization. Policies define minimum required claims and assurance levels. Delegation scope constrains delegate actions to specific policy IDs. Delegation expiry enforces time-bounded privilege. | `lib/handshake/policy.js`, `lib/handshake/bind.js` (`checkDelegation()`) |
| **AU-2** | Event Logging | All 17 command types across all aggregate types (receipt, commit, dispute, report, handshake) produce protocol events. Handshake lifecycle events cover all state transitions. | `lib/protocol-write.js` (`appendProtocolEvent()`), `lib/handshake/events.js` (`requireHandshakeEvent()`) |
| **AU-3** | Content of Audit Records | Protocol events record: `event_id`, `aggregate_type`, `aggregate_id`, `command_type`, `parent_event_hash`, `payload_hash`, `actor_authority_id`, `idempotency_key`, `created_at`. Handshake events record: `event_id`, `handshake_id`, `event_type`, `actor_entity_ref`, `detail`, `created_at`. | `protocol_events` schema, `handshake_events` schema |
| **AU-6** | Audit Record Review | Protocol events and handshake events are queryable by aggregate, actor, time range, and event type. Rejection reason codes provide structured categorization for review. `scripts/replay-protocol.js` supports event replay. | Event tables, `scripts/replay-protocol.js` |
| **AU-10** | Non-Repudiation | Actor identity derived from authentication (not self-asserted). Binding hash content-addresses all action parameters. Events written before state changes with database-enforced append-only. Parent event hashing provides chain integrity. | Invariants 2, 9, 10 |
| **AU-12** | Audit Record Generation | Event generation is mandatory: `requireHandshakeEvent()` throws `EVENT_WRITE_REQUIRED` on failure; `appendProtocolEvent()` throws `EVENT_PERSISTENCE_FAILED` on failure. If the event cannot be written, the operation does not proceed. | `lib/handshake/events.js`, `lib/protocol-write.js` |
| **IA-2** | Identification and Authentication | Actor identity resolved from authentication middleware. Handshake parties must have `entity_ref` matching the authenticated entity. System actor has explicit bypass (documented exception). | Invariant 2, `lib/handshake/present.js` |
| **IA-4** | Identifier Management | Entity references are unique, registry-managed. Authority `key_id` values are unique identifiers for issuer verification. Handshake IDs, event IDs, and binding IDs are system-generated UUIDs. | Entity registry, `authorities` table, UUID generation |
| **IA-5** | Authenticator Management | Authority lifecycle management: valid, revoked, expired, not-yet-valid states. Revoked authorities immediately untrusted. CI guard prevents embedded key trust. | `lib/handshake/present.js` (status tracking), `scripts/check-protocol-discipline.js` (`checkEmbeddedIssuerKeys()`) |
| **SC-7** | Boundary Protection | Write guard enforces trust-table boundary. Runtime proxy (`getGuardedClient()`) blocks direct mutations on 13 trust tables. CI guards enforce at build time. Three-layer defense prevents bypass. | `lib/write-guard.js`, Invariant 1 |
| **SC-13** | Cryptographic Protection | SHA-256 binding hashes for transaction binding. SHA-256 policy hashes for drift detection. 32-byte random nonces (via `crypto.randomBytes(32)`). Content-addressed idempotency keys. | `lib/handshake/invariants.js`, `lib/handshake/create.js`, `lib/protocol-write.js` |
| **SI-10** | Information Input Validation | `assertInvariants()` validates structural protocol invariants. Type-specific validators enforce schema compliance. `CANONICAL_BINDING_FIELDS` enforces exact field set (no missing, no extra). | `lib/protocol-write.js` (step 1-2), `lib/handshake/invariants.js` |

---

## FFIEC Alignment

### Authentication and Access Risk Management

**FFIEC Handbook Reference**: Authentication and Access to Financial Institution Services and Systems

EP extends authentication from session-level to action-level:

| FFIEC Requirement | EP Mechanism |
|---|---|
| Layered security approach | Three layers: identity (auth middleware), authority (registry resolution), action binding (handshake) |
| Risk-based authentication | Policy-driven assurance levels. Policies specify minimum claim requirements and assurance thresholds per action type. |
| Customer session management | Handshake bindings have configurable TTL [60s, 1800s], independent of session duration. Expired bindings are rejected. |
| Transaction signing / out-of-band verification | Canonical binding hash content-addresses all transaction parameters. Any parameter change invalidates the binding. |
| Activity monitoring | Append-only protocol events and handshake events with structured rejection reason codes for real-time monitoring. |

### Third-Party Risk Management

**FFIEC Handbook Reference**: Third-Party Relationships: Risk Management Guidance

EP provides controls for delegated and third-party actions:

| FFIEC Requirement | EP Mechanism |
|---|---|
| Due diligence on third parties | Authority registry with explicit trust registration. Third-party issuers must be registered before their credentials are trusted. |
| Contractual scope definition | Delegation scope (list of policy IDs or wildcard) with expiry. Delegates cannot act outside their granted scope. |
| Ongoing monitoring | All delegated actions produce protocol events and handshake events with delegation chain attribution. |
| Audit and reporting | Full event reconstruction for delegated actions. Delegation chain preserved in handshake records. |
| Incident response | Revocation of delegated authority immediately prevents future handshake verifications against that authority. |

### Operational Resilience

**FFIEC Handbook Reference**: Business Continuity Management

EP supports operational resilience through:

| FFIEC Requirement | EP Mechanism |
|---|---|
| Critical operation identification | Policy-driven classification. Actions requiring handshake verification are explicitly designated through policy configuration. |
| Recovery and reconstruction | Append-only event logs with parent event hashing enable full state reconstruction. `scripts/replay-protocol.js` supports forensic event replay. |
| Testing | 47 conformance invariant tests and 24 adversarial attack tests provide continuous verification of control effectiveness. |
| Audit trail integrity | Database triggers prevent UPDATE and DELETE on event tables. Write guard prevents direct trust-table mutations. |
