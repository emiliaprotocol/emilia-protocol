# EP Core Substrate -- Trust Objects

The EMILIA Protocol's trust layer is built on six core trust objects. Every trust-changing state transition flows through `protocolWrite()` (the single choke point), which enforces validation, idempotency, event persistence, and telemetry for each object type.

All six object types are protected by the write guard (`lib/write-guard.js`), which blocks direct mutations on their backing tables at runtime. Only the canonical write layer may modify them.

---

## Receipts

**Aggregate type**: `receipt`
**Backing table**: `receipts`
**Command types**: `submit_receipt`, `submit_auto_receipt`, `confirm_receipt`

Receipts are behavioral records of entity interactions. They capture what one entity observed about another entity's behavior in a specific context. Receipts are the atomic unit of trust evidence in EP.

Key properties:
- **Bilateral confirmation**: A receipt can be unilaterally submitted, but bilateral confirmation (via `confirm_receipt`) strengthens its evidentiary weight. The confirming entity attests that the interaction occurred as described.
- **Auto-receipts**: System-generated receipts (`submit_auto_receipt`) follow the exact same write path as manual receipts, ensuring path unity. This is enforced by the `receipt-path-unity` test.
- **Idempotency**: Duplicate receipt submissions for the same interaction are deduplicated via SHA-256 idempotency keys (migration 034).

---

## Commits

**Aggregate type**: `commit`
**Backing table**: `commits`
**Command types**: `issue_commit`, `verify_commit`, `revoke_commit`

Commits are pre-authorization trust decisions -- signed tokens issued before an action is taken. They represent an entity's declared intent to act in a specific way, creating a verifiable commitment that can later be checked against actual behavior.

Key properties:
- **Lifecycle**: `issued` -> `verified` -> `fulfilled` (or `revoked` at any point).
- **Revocation requires reason**: The `revoke_commit` validator enforces that a reason is always provided, creating an audit trail for broken commitments.
- **Verification**: `verify_commit` confirms that the commit's conditions are met and the issuing entity still has authority.

---

## Handshakes

**Aggregate type**: `handshake`
**Backing tables**: `handshakes`, `handshake_parties`, `handshake_presentations`, `handshake_bindings`, `handshake_results`, `handshake_policies`, `handshake_events`, `handshake_consumptions`
**Command types**: `initiate_handshake`, `add_presentation`, `verify_handshake`, `revoke_handshake`

Handshakes are multi-party trust establishment ceremonies with cryptographic binding. They allow two or more entities to mutually verify identity, credentials, and intent before engaging in a trust-bearing interaction.

Key properties:
- **Modes**: `basic`, `mutual`, `selective`, `delegated` -- each mode defines different requirements for party participation and disclosure.
- **Binding material**: Canonical fields (`CANONICAL_BINDING_FIELDS`) are hashed to produce a binding that ties the handshake to a specific action, policy, and party set. The field list is frozen and versioned (`BINDING_MATERIAL_VERSION`).
- **Invariant enforcement**: Ten security invariants (expiry, party completeness, binding validity, issuer trust, authority revocation, assurance level, duplicate prevention, interaction binding, role spoofing prevention, result immutability) are checked via pure functions in `lib/handshake/invariants.js`.
- **Lifecycle states**: `initiated` -> `pending_verification` -> `verified` (or `rejected`, `expired`, `revoked`).
- **Assurance levels**: `low` < `medium` < `substantial` < `high`, with rank enforcement ensuring policies can mandate minimum assurance.

---

## Disputes

**Aggregate type**: `dispute`
**Backing table**: `disputes`
**Command types**: `file_dispute`, `resolve_dispute`, `respond_dispute`, `appeal_dispute`, `resolve_appeal`, `withdraw_dispute`

Disputes are the challenge mechanism for trust claims. Any entity can file a dispute against a receipt, triggering a structured adjudication process with procedural justice guarantees.

Key properties:
- **State machine**: Disputes follow a strict state machine (`DISPUTE_STATES` in `lib/procedural-justice.js`) with validated transitions. Invalid state transitions are rejected.
- **Abuse detection**: Filing a dispute triggers abuse detection checks (`checkAbuse`) to prevent weaponized dispute flooding.
- **Response right**: The disputed party has the right to respond (`respond_dispute`) with evidence before resolution.
- **Appeal mechanism**: After initial resolution, parties can appeal (`appeal_dispute`, minimum 10-character reason required). Appeals go through a separate resolution path (`resolve_appeal`).
- **Withdrawal**: The filing party can withdraw a dispute (`withdraw_dispute`), which is recorded but does not erase the dispute record.
- **Operator authorization**: Resolution and appeal resolution require an `operator_id`, enforcing that adjudication decisions come from authorized operators.

---

## Trust Reports

**Aggregate type**: `report`
**Backing table**: `trust_reports`
**Command types**: `file_report`

Trust reports are community-sourced trust signals that capture entity behavior observations outside the receipt framework. They provide a lower-friction mechanism for reporting patterns of concern.

Key properties:
- **Report types**: Each report has a `report_type` classification and a required `description`.
- **Abuse detection**: Report filing triggers abuse detection checks to prevent coordinated report flooding.
- **Distinct from disputes**: Reports are observational signals, not challenges to specific receipts. They feed into trust scoring but do not trigger adjudication.

---

## Protocol Events

**Aggregate type**: N/A (meta-object)
**Backing table**: `protocol_events`

Protocol events form the immutable audit trail of every trust-changing state transition in the system. Every successful `protocolWrite()` call appends an event to this table. If event persistence fails, the entire write is rejected -- an unlogged trust transition is never acceptable.

Key properties:
- **Append-only**: Events are never updated or deleted. They form a hash-chained audit log.
- **Required fields**: `event_id` (UUID), `aggregate_type`, `aggregate_id`, `command_type`, `payload_hash` (SHA-256 of canonicalized payload), `actor_authority_id`, `idempotency_key`, `created_at`.
- **Parent chaining**: Each event can reference a `parent_event_hash` to chain events within the same aggregate.
- **Hard requirement**: The `appendProtocolEvent` function is awaited and its failure causes the entire `protocolWrite()` to throw a `ProtocolWriteError` with code `EVENT_PERSISTENCE_FAILED`.
- **Telemetry**: After successful event persistence, structured telemetry is emitted for observability pipelines.

---

## Cross-Cutting Enforcement

### Write Guard (`lib/write-guard.js`)

The write guard is a runtime Proxy that intercepts `insert`, `update`, `upsert`, and `delete` calls on all 13 trust-bearing tables. Route handlers receive a guarded client via `getGuardedClient()`. Attempting to mutate a trust table through the guarded client throws immediately with `WRITE_DISCIPLINE_VIOLATION`.

The guard list is frozen (`Object.freeze`) and includes: `receipts`, `commits`, `disputes`, `trust_reports`, `protocol_events`, `handshakes`, `handshake_parties`, `handshake_presentations`, `handshake_bindings`, `handshake_results`, `handshake_policies`, `handshake_events`, `handshake_consumptions`.

### CI Enforcement (`scripts/check-write-discipline.js`)

A static analysis script runs in CI to verify that no route file under `app/api/` imports forbidden canonical functions directly (bypassing `protocolWrite()`). It also verifies that route files use `getGuardedClient()` instead of `getServiceClient()`, with an explicit allowlist for routes that are pending migration.

### Conformance Test Suite (`tests/conformance.test.js`)

47 structural invariant tests verify that the protocol's internal consistency holds: every command type has complete coverage (validator + handler + aggregate), the write guard covers all trust tables, binding fields are canonical and frozen, assurance levels are properly ordered, and the CI script covers all canonical functions.
