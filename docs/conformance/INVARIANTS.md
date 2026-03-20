# EMILIA Protocol -- Conformance Invariants

These are the 10 invariants that EP enforces. Each invariant is a property that must hold for every trust-changing operation. Violation of any invariant rejects the operation.

---

## Invariant 1: All trust-changing writes go through `protocolWrite()`

**Statement**: Every insert, update, upsert, or delete on a trust-bearing table must flow through `protocolWrite()` in `lib/protocol-write.js`. No route handler, service function, or utility may write to trust tables directly.

**Enforcement mechanism**:
- **Runtime**: `getGuardedClient()` in `lib/write-guard.js` returns a Proxy that throws `WRITE_DISCIPLINE_VIOLATION` on `insert()`, `update()`, `upsert()`, or `delete()` calls targeting any of the 13 trust tables.
- **CI (check-write-discipline.js)**: Scans `app/api/**/route.{js,ts}` for imports of forbidden canonical functions and `getServiceClient` usage. Exit code 1 on violation.
- **CI (check-protocol-discipline.js)**: Scans all application and library files for `.from('trust_table').insert()` patterns outside the allowlisted canonical write layer.

**Test coverage**: Write-guard unit tests verify that guarded client blocks mutations on each trust table. CI scripts run on every build.

**Failure mode**: Runtime -- throws `Error` with `WRITE_DISCIPLINE_VIOLATION` prefix. CI -- build fails with violation report listing file, line, and forbidden function.

---

## Invariant 2: Actor identity is derived from auth, never request body

**Statement**: The `actor` field in a `protocolWrite()` command must originate from the authentication middleware (session, JWT, API key resolution). It must never be taken from `request.body`, query parameters, or any client-supplied field.

**Enforcement mechanism**:
- **Architectural**: `resolveAuthority()` in `lib/protocol-write.js` normalizes the actor from `command.actor`, which route handlers must set from the authenticated session.
- **Handshake binding**: `initiateHandshake()` compares the actor's entity ID against the initiator party's `entity_ref`. Mismatch throws `INITIATOR_BINDING_VIOLATION` (403).
- **Presentation binding**: `_handleAddPresentation()` compares authenticated entity against party's `entity_ref`. Mismatch throws `ROLE_SPOOFING` (403).

**Test coverage**: Handshake attack tests verify that mismatched actor/party combinations are rejected.

**Failure mode**: `HandshakeError` with code `INITIATOR_BINDING_VIOLATION`, `DELEGATE_BINDING_VIOLATION`, or `ROLE_SPOOFING` (HTTP 403).

---

## Invariant 3: Authority roots from trusted registry

**Statement**: Issuer trust must be resolved by looking up the issuer's `key_id` in the `authorities` table. Trust must never be derived from keys, certificates, or credentials embedded in the presentation payload.

**Enforcement mechanism**:
- **Runtime**: `_handleAddPresentation()` in `lib/handshake/present.js` queries `authorities` table by `key_id`. Unknown issuers default to `issuerTrusted = false`.
- **CI**: `checkEmbeddedIssuerKeys()` in `scripts/check-protocol-discipline.js` detects patterns like `presentation.publicKey`, `presentation.signingKey`, `payload.key` in handshake code. Critical violation if found.
- **Invariant function**: `checkIssuerTrusted()` in `lib/handshake/invariants.js` verifies issuer is in the provided authorities list.

**Test coverage**: Invariant unit tests verify that presentations with unknown, revoked, expired, and not-yet-valid issuers are handled correctly.

**Failure mode**: Presentation stored with `verified = false` and explicit `issuer_status` (e.g., `authority_not_found`, `authority_revoked`). Verification pipeline adds `issuer_revoked_{role}` or `unverified_presentation_{role}` reason codes.

---

## Invariant 4: No embedded-key trust

**Statement**: The system must never trust a cryptographic key that is presented inline in a credential or request payload. All keys must be resolved from the authority registry.

**Enforcement mechanism**:
- **CI**: `checkEmbeddedIssuerKeys()` scans for `presentation.publicKey`, `presentation.signingKey`, `payload.key` patterns. Flagged as critical violation.
- **Architectural**: The `_handleAddPresentation()` function only accepts `issuer_ref` (a reference to a registry entry), never a key value.

**Test coverage**: CI script executes on every build. No runtime path exists to accept embedded keys.

**Failure mode**: CI build failure with message: `Direct trust of embedded issuer key -- keys must come from authority registry, not embedded in presentations`.

---

## Invariant 5: No production ephemeral trust

**Statement**: In production, trust decisions must not be based on ephemeral or unverified credentials. Every trust-bearing assertion must be traceable to a registered authority.

**Enforcement mechanism**:
- **Default fail-closed**: `_handleAddPresentation()` initializes `issuerTrusted = false` and `issuerTrustReason = 'unknown'` before any resolution. Trust is only granted after positive verification against the authority registry.
- **Self-asserted handling**: Self-asserted presentations (`issuer_ref` is null) are marked `issuerTrusted = true` with `issuerTrustReason = 'self_asserted'`, but their trust value is determined by policy rules at verification time, not by the assertion itself.

**Test coverage**: Invariant tests verify default untrusted state. Verification tests confirm that unverified presentations produce rejection reason codes.

**Failure mode**: Presentations with unknown issuers are stored with `verified = false`. At verification, they produce `unverified_presentation_{role}` reason codes, leading to rejection or partial outcome.

---

## Invariant 6: Handshake presentations require role-authorized actor

**Statement**: An entity may only submit a presentation for a party role that the entity is registered for. The authenticated entity must match the party's `entity_ref`.

**Enforcement mechanism**:
- **Runtime**: `_handleAddPresentation()` in `lib/handshake/present.js`:
  ```javascript
  if (authenticatedEntity !== 'system' && party.entity_ref !== authenticatedEntity) {
    throw new HandshakeError('Authenticated entity does not match handshake party', 403, 'ROLE_SPOOFING');
  }
  ```
- **Invariant function**: `checkNoRoleSpoofing()` in `lib/handshake/invariants.js` performs the same check as a pure function.
- **Initiation binding**: `initiateHandshake()` enforces that the initiator's `entity_ref` matches the actor (except in delegated mode, where the delegate must match).

**Test coverage**: Attack tests verify that cross-party presentation attempts are rejected.

**Failure mode**: `HandshakeError` with code `ROLE_SPOOFING` (HTTP 403).

---

## Invariant 7: Policy resolution failure rejects

**Statement**: If a handshake has a `policy_id` and the policy cannot be loaded at verification time, the handshake must be rejected. There is no fallback to a default or permissive policy.

**Enforcement mechanism**:
- **Runtime**: `_handleVerifyHandshake()` in `lib/handshake/verify.js`:
  - `resolvePolicy()` exception: adds `policy_load_failed` reason code.
  - `resolvePolicy()` returns null: adds `policy_not_found` reason code.
  - Policy hash mismatch: adds `policy_hash_mismatch` reason code.
  - Any of these reason codes results in `rejected` outcome.

**Test coverage**: Verification tests with missing/modified policies confirm rejection.

**Failure mode**: Handshake verification returns `{ outcome: 'rejected', reason_codes: ['policy_load_failed'] }` or `['policy_not_found']`.

---

## Invariant 8: Accepted authorization artifacts may be consumed exactly once

**Statement**: A verified handshake binding may authorize exactly one downstream action. Once consumed, it cannot be consumed again.

**Enforcement mechanism**:
- **Hard gate**: `_handleVerifyHandshake()` checks `consumed_at` at the top of the function. Already-consumed bindings are rejected immediately with `binding_already_consumed`.
- **Conditional update**: Consumption update uses `.is('consumed_at', null)` filter, making it a compare-and-swap that only succeeds if the binding has not been consumed.
- **Binding check**: `checkBinding()` in `lib/handshake/bind.js` adds `binding_already_consumed` if `binding.consumed_at` is set.
- **Database constraint**: Unique constraint on `handshake_consumptions` table prevents duplicate consumption records.
- **Write guard**: `handshake_consumptions` is in `TRUST_TABLES`, preventing direct writes from route handlers.

**Test coverage**: Verification tests confirm that double-consumption attempts are rejected. Race condition tests verify conditional update behavior.

**Failure mode**: Second consumption attempt returns `{ outcome: 'rejected', reason_codes: ['binding_already_consumed'] }`.

---

## Invariant 9: State transitions must emit durable events before state change

**Statement**: Every trust-changing state transition must have a corresponding event record written to `protocol_events` (for all commands) or `handshake_events` (for handshake lifecycle) before the state change is materialized. If the event write fails, the state change must not proceed.

**Enforcement mechanism**:
- **Protocol events**: `appendProtocolEvent()` in `lib/protocol-write.js` is called inside `protocolWrite()` after the handler executes but as a mandatory step. Throws `ProtocolWriteError` with code `EVENT_PERSISTENCE_FAILED` on failure.
- **Handshake events**: `requireHandshakeEvent()` in `lib/handshake/events.js` is called in `_handleInitiateHandshake`, `_handleAddPresentation`, `_handleVerifyHandshake`, and `_handleRevokeHandshake` before any `.update()` calls. Throws on failure with `EVENT_WRITE_REQUIRED` message.
- **Ordering**: All handshake lifecycle functions include explicit comments documenting the event-before-state-change ordering.
- **Append-only**: Database triggers on `protocol_events` and `handshake_events` tables prevent UPDATE and DELETE.

**Test coverage**: Event recording tests verify that events are written for each lifecycle transition. Failure mode tests verify that failed event writes prevent state changes.

**Failure mode**: `Error` with `EVENT_WRITE_REQUIRED` prefix (handshake events) or `ProtocolWriteError` with code `EVENT_PERSISTENCE_FAILED` (protocol events). The entire operation is rolled back or rejected.

---

## Invariant 10: Canonical binding hash must match exact action context

**Statement**: The binding hash computed at handshake initiation must content-address all fields that define the action context. Any modification to the action, parties, policy, payload, nonce, or expiry produces a different hash. At verification time, any mismatch between stored and provided hashes results in rejection.

**Enforcement mechanism**:
- **Field completeness**: `_handleInitiateHandshake()` in `lib/handshake/create.js` asserts that all `CANONICAL_BINDING_FIELDS` are present in the binding material and no extra fields exist. Missing or extra fields throw `BINDING_INVARIANT_VIOLATION`.
- **Canonical fields** (from `lib/handshake/invariants.js`): `action_type`, `resource_ref`, `policy_id`, `policy_version`, `policy_hash`, `interaction_id`, `party_set_hash`, `payload_hash`, `context_hash`, `nonce`, `expires_at`, `binding_material_version`.
- **Hash computation**: `SHA-256(JSON.stringify(bindingMaterial, sorted_keys))`.
- **Verification checks**: `_handleVerifyHandshake()` checks `action_hash`, `policy_hash`, `payload_hash`, and `nonce` against stored values. Mismatches produce explicit reason codes.
- **Invariant function**: `checkBindingValid()` in `lib/handshake/invariants.js` verifies nonce presence and payload hash match.
- **Version control**: `BINDING_MATERIAL_VERSION` (currently 1) is included in the binding material. Changing the canonical field set requires incrementing this version.

**Test coverage**: Binding tests verify hash computation determinism. Invariant tests verify that modified fields produce different hashes and that missing/extra fields are rejected.

**Failure mode**: At initiation -- `Error` with `BINDING_INVARIANT_VIOLATION`. At verification -- reason codes: `action_hash_mismatch`, `policy_hash_mismatch`, `payload_hash_mismatch`, `nonce_mismatch`, resulting in `rejected` outcome.
