# EMILIA Protocol -- Failure Modes

## Scope

This document catalogs how EP behaves when components fail. The governing principle is fail-closed: when a trust-bearing decision cannot be made with full confidence, the system rejects the action. There is no silent degradation, no default-allow, and no fallback to weaker trust.

---

## 1. Event Write Failure During Mutation

**Scenario**: `requireHandshakeEvent()` or `appendProtocolEvent()` throws during a state-changing operation.

**Behavior**: The mutation does not proceed. Event writes are ordered before state changes (event-first ordering). If the event cannot be persisted, the state transition is abandoned.

**Enforcement**:
- `requireHandshakeEvent()` in `lib/handshake/events.js`: Throws `EVENT_WRITE_REQUIRED` with the handshake ID and event type. Called by `create`, `present`, `verify`, and `finalize` handlers.
- `appendProtocolEvent()` in `lib/protocol-write.js`: Throws `ProtocolWriteError` with code `EVENT_PERSISTENCE_FAILED`.

**Rationale**: An unlogged trust transition is invisible to audit. A mutation without an event record violates the protocol's accountability guarantee. The safe failure is to reject the mutation entirely.

**Recovery**: Retry the operation. If event persistence is systematically failing (database down), all trust-bearing operations halt until the event store is restored.

---

## 2. Database Unavailable

**Scenario**: The primary database (Supabase/PostgreSQL) is unreachable or returns connection errors.

**Behavior**: All trust-bearing operations fail. No handshakes can be initiated, no presentations added, no verifications performed.

**Enforcement**:
- Every handler (`_handleInitiateHandshake`, `_handleAddPresentation`, `_handleVerifyHandshake`) wraps database calls with error handling that throws `HandshakeError` with code `DB_ERROR` (HTTP 500).
- `lib/errors.js`: Trust-critical paths are annotated with the comment "MUST fail closed -- never degrade gracefully."
- `lib/delegation.js`: Delegation creation explicitly fails closed when the delegations table is missing.

**What does NOT happen**: The system does not cache previous authorization decisions and replay them. There is no "offline mode" for trust decisions. There is no in-memory fallback registry.

---

## 3. Policy Lookup Failure

**Scenario**: `resolvePolicy()` throws an error or returns `null` during handshake verification.

**Behavior**: The handshake is rejected.

**Enforcement** (from `lib/handshake/verify.js`):
- If `resolvePolicy()` throws: `policy_load_failed` is added to reason codes.
- If `resolvePolicy()` returns `null`: `policy_not_found` is added to reason codes.
- Either condition results in handshake rejection. There is no "accept with no policy" path.

**Rationale**: A missing policy means the system cannot determine what trust requirements apply. Proceeding without requirements is equivalent to default-allow, which EP explicitly prohibits.

---

## 4. Binding Hash Mismatch

**Scenario**: At verification time, the re-computed policy hash does not match the `policy_hash` stored at initiation.

**Behavior**: `policy_hash_mismatch` is added to reason codes. The handshake is rejected.

**Enforcement** (from `lib/handshake/verify.js`):
- Policy is re-loaded and re-hashed at verification time.
- If `SHA-256(JSON.stringify(policy.rules, sorted_keys))` differs from the stored `policy_hash`, the mismatch is recorded.

**Rationale**: Policy hash pinning prevents policy drift -- the attack where policy rules are weakened between initiation and verification. A mismatch indicates that the trust requirements have changed, and the binding was made under different assumptions.

**Recovery**: The initiating system must create a new handshake under the current policy.

---

## 5. Expired Handshake

**Scenario**: A handshake binding's `expires_at` timestamp is in the past when verification is attempted.

**Behavior**: The binding is rejected with `binding_expired`.

**Enforcement**:
- `checkBinding()` in `lib/handshake/bind.js`: `if (new Date(binding.expires_at) < new Date()) reason_codes.push('binding_expired')`.
- `checkNotExpired()` in `lib/handshake/invariants.js`: Returns `BINDING_EXPIRED` failure.
- Verification outcome is set to `expired`.

**What does NOT happen**: Expired bindings cannot be revived, extended, or renewed. A new handshake must be initiated. The TTL is clamped to `[60s, 1800s]` at initiation and cannot be modified afterward.

---

## 6. Consumed Handshake

**Scenario**: A verification request arrives for a handshake whose binding has already been consumed.

**Behavior**: Immediate rejection with `binding_already_consumed`.

**Enforcement** (from `lib/handshake/verify.js`):
- Hard gate at the top of `_handleVerifyHandshake()`: If `existingBinding?.consumed_at` is set, the handler returns `rejected` with `binding_already_consumed` before any further processing.
- This is a fast-path rejection -- no invariants are run, no policy is loaded.

**Rationale**: One-time consumption is a core replay resistance mechanism. Re-consuming a binding would authorize a second action from a single verification.

---

## 7. Authority Chain Broken

**Scenario**: Any link in the authority chain (trust root, issuer, delegation, actor binding) is invalid.

**Behavior**: The handshake is rejected. There is no fallback to a weaker trust level.

**Specific failures**:

| Broken link | Error code | HTTP status |
|---|---|---|
| Trust root missing | `authority_not_found` | Rejection reason |
| Trust root revoked | `authority_revoked` | Rejection reason |
| Trust root expired | `authority_expired` | Rejection reason |
| Trust root not yet valid | `authority_not_yet_valid` | Rejection reason |
| Delegation expired | `delegation_expired` | Rejection reason |
| Delegation out of scope | `delegation_out_of_scope` | Rejection reason |
| Actor does not match initiator | `INITIATOR_BINDING_VIOLATION` | 403 |
| Actor does not match delegate | `DELEGATE_BINDING_VIOLATION` | 403 |
| Actor does not match party | `ROLE_SPOOFING` | 403 |

**What does NOT happen**: The system does not fall back to self-asserted trust when the registry is unavailable. It does not accept a wider delegation scope than what was granted. It does not allow a different actor to present on behalf of a party.

---

## 8. Network Partition

**Scenario**: The application server can reach the database but not an external service (or vice versa), or internal services cannot communicate.

**Behavior**: Authorization decisions fail closed.

- If the database is reachable but the authority registry query fails: `authority_table_missing` / `registry_unavailable`. Presentations from external issuers are rejected.
- If the event store is unreachable: Event-first ordering prevents any state change.
- If the application cannot reach the database at all: All operations fail with `DB_ERROR`.

**Rationale**: A network partition creates uncertainty about the current state of trust roots, delegations, and consumption records. Acting on stale or incomplete trust data is worse than rejecting the action.

---

## 9. Clock Skew

**Scenario**: The application server's clock is out of sync with the database server or with the timestamps stored in authority validity windows.

**Behavior**: EP uses server-side timestamps for all trust-bearing time comparisons.

**Mitigations**:
- **Binding expiry**: `expires_at` is computed server-side at initiation using `new Date()`. Verification compares against server-side `new Date()`. Both operations use the same clock source (the application server).
- **Authority validity windows**: `valid_from` and `valid_to` are compared against server-side `new Date()` during presentation processing.
- **Bounded tolerance**: Binding TTL is clamped to `[60s, 1800s]`. A clock skew of a few seconds is absorbed by the minimum 60-second TTL. Skew exceeding the TTL is operationally catastrophic and must be resolved at the infrastructure level (NTP).
- **Database timestamps**: `consumed_at`, `created_at`, and event timestamps use `new Date().toISOString()` from the application server, not database-generated timestamps. This avoids cross-clock comparison.

**What is NOT done**: EP does not implement Lamport clocks, vector clocks, or distributed timestamp consensus. Clock synchronization is an infrastructure concern delegated to NTP.

---

## 10. Concurrent Race Conditions

**Scenario**: Two concurrent requests attempt to consume the same handshake binding, or two concurrent initiations use the same idempotency key.

**Behavior**: Database-level constraints resolve the race deterministically.

**Binding consumption race**:
1. Both requests pass the `consumed_at` hard gate (both see `NULL`).
2. Both proceed through the verification pipeline.
3. Both attempt the conditional update: `.update({consumed_at: ...}).is('consumed_at', null)`.
4. First writer wins -- the update affects one row.
5. Second writer's update affects zero rows -- consumption does not occur.
6. Unique constraint on `handshake_consumptions` provides a secondary guard.

**Idempotency race**:
- If two concurrent `initiateHandshake()` calls use the same `idempotency_key`, the database unique constraint on `idempotency_key` prevents duplicate handshake creation. One succeeds; the other receives the existing handshake with `idempotent: true`.

**Rationale**: Application-level locks (mutexes, advisory locks) are fragile under horizontal scaling. Database constraints are atomic and survive process crashes. EP relies on the database as the serialization point for all trust-bearing state transitions.
