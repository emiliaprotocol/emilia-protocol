# EMILIA Protocol -- Event Model

## Ordering Principle

**Every state transition emits an event BEFORE the state change is materialized.**

This ordering is intentional and appears throughout the codebase with explicit comments:

```
// Event is written BEFORE state change: if event fails, state stays unchanged (safe).
// If event succeeds but state change fails, we have a logged but uncommitted transition (safe -- retry).
```

The rationale:

1. **If event write fails**: State change does not proceed. The system remains in its previous consistent state. No trust-changing operation goes unlogged.
2. **If event write succeeds but state change fails**: The event log shows an attempted transition. The operation can be retried. The event log is a superset of actual state changes, never a subset.
3. **If state change happened first and event write failed**: The system would have a trust-changing state change with no audit trail. This is the unacceptable scenario that event-first ordering prevents.

## Two Event Systems

### `protocol_events` Table

Written by `appendProtocolEvent()` inside `protocolWrite()`. Covers all 17 command types across all aggregate types.

#### Fields

| Field | Type | Description |
|---|---|---|
| `event_id` | UUID | `crypto.randomUUID()` |
| `aggregate_type` | string | `receipt`, `commit`, `dispute`, `report`, or `handshake` |
| `aggregate_id` | string | The entity's primary key for this aggregate |
| `command_type` | string | The command that produced this event (one of 17 COMMAND_TYPES) |
| `parent_event_hash` | string | Hash of previous event for this aggregate (reserved for event chaining) |
| `payload_hash` | string | `SHA-256(JSON.stringify(payload, sorted_keys))` |
| `actor_authority_id` | string | Resolved actor ID from command |
| `idempotency_key` | string | `SHA-256(command.type + actor + JSON.stringify(input))` |
| `created_at` | ISO 8601 string | Timestamp of event creation |

#### Persistence Guarantee

`appendProtocolEvent()` throws `ProtocolWriteError` with code `EVENT_PERSISTENCE_FAILED` if the insert fails. The error message:

```
EVENT_WRITE_REQUIRED: Failed to persist protocol event for {command_type}
on {aggregate_type}/{aggregate_id}: {db_error}.
State transition REJECTED -- every transition must be logged.
```

This is a hard requirement. The entire `protocolWrite()` operation fails if the event cannot be persisted.

### `handshake_events` Table

Written by handshake lifecycle functions. Provides a handshake-specific audit trail separate from the general protocol event log.

#### Fields

| Field | Type | Description |
|---|---|---|
| `event_id` | UUID | `crypto.randomUUID()` |
| `handshake_id` | UUID | The handshake this event belongs to |
| `event_type` | string | Lifecycle event type (see below) |
| `actor_entity_ref` | string | Resolved actor entity reference |
| `detail` | JSON | Event-specific metadata |
| `created_at` | ISO 8601 string | Timestamp |

#### Event Types

From `HANDSHAKE_EVENT_TYPES` in `lib/handshake/events.js`:

```
handshake_created
handshake_presented
handshake_verification_started
handshake_verified
handshake_rejected
handshake_expired
handshake_cancelled
handshake_revoked
```

Additionally, the lifecycle functions emit these event_type values directly:

```
initiated              -- emitted by _handleInitiateHandshake
presentation_added     -- emitted by _handleAddPresentation
status_changed         -- emitted by _handleAddPresentation (initiated -> pending_verification)
verified               -- emitted by _handleVerifyHandshake (on accepted outcome)
rejected               -- emitted by _handleVerifyHandshake (on rejected outcome)
expired                -- emitted by _handleVerifyHandshake (on expired outcome)
revoked                -- emitted by _handleRevokeHandshake
```

## Append-Only Enforcement

Both `protocol_events` and `handshake_events` tables are append-only. Database triggers prevent `UPDATE` and `DELETE` operations on these tables. Only `INSERT` is permitted.

This ensures:
- Events cannot be retroactively altered.
- The event log is a complete, immutable history of all state transitions.
- Any state can be reconstructed by replaying events in order.

## `requireHandshakeEvent` vs `emitHandshakeEvent`

### `requireHandshakeEvent()`

**Mandatory event recorder for state-transition events.** If this fails, the caller MUST reject the operation.

- Throws on failure with message: `EVENT_WRITE_REQUIRED: Failed to record mandatory event "{event_type}" for handshake {handshake_id}: {error}. State transition REJECTED -- every transition must be logged.`
- Used for: `initiated`, `presentation_added`, `status_changed`, `verified`, `rejected`, `expired`, `revoked`.
- Returns the inserted event record on success.

### `emitHandshakeEvent()`

**Best-effort event emitter for non-critical telemetry.** Degrades gracefully if the table does not exist (pre-migration scenarios).

- Catches all errors. If the table is missing, suppresses silently. Other errors are logged as warnings.
- Used for informational/telemetry events that do not represent state transitions.
- Does NOT throw on failure.

### Decision Rule

If the event represents a state transition that changes trust state: use `requireHandshakeEvent()`.
If the event is informational or telemetry: use `emitHandshakeEvent()`.

## `recordHandshakeEvent()` (Legacy API)

The `recordHandshakeEvent()` function in `lib/handshake/events.js` is the original event recording API. It:

- Validates `event_type` against `HANDSHAKE_EVENT_TYPES`.
- Generates an idempotency key: `SHA-256(handshake_id + event_type + actor_id)`.
- Checks for existing events with the same idempotency key (dedup).
- Inserts if no duplicate exists.
- Throws `HandshakeEventError` on failure.

This function accepts a Supabase client as its first argument (dependency injection), unlike `requireHandshakeEvent()` which creates its own client internally.

## Reconstruction Principle

The event log is the source of truth. Given the complete event history for an aggregate, the current state can be reconstructed by replaying events in `created_at` order.

For protocol events, each event records the `command_type` and `payload_hash`, allowing full reconstruction of what command produced what state change.

For handshake events, the `detail` JSON captures the context of each transition (e.g., `{ from: 'initiated', to: 'pending_verification', trigger: 'presentation_added' }`), enabling precise state replay.

The `parent_event_hash` field in `protocol_events` is reserved for future event chaining, which will enable cryptographic verification of event ordering (currently set to `null`).
