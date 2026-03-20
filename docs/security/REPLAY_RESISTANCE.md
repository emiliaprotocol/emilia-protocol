# EMILIA Protocol -- Replay Resistance

## Overview

Replay resistance in EP is achieved through six independent mechanisms that work in concert. Any single mechanism is insufficient; the combination provides defense in depth.

## 1. Nonce

**Generation**: `crypto.randomBytes(32).toString('hex')` -- 32 bytes of cryptographic randomness, hex-encoded to 64 characters.

**Source**: `newNonce()` in `lib/handshake/invariants.js`.

**Lifecycle**:
- Generated at handshake initiation in `initiateHandshake()` (`lib/handshake/create.js`).
- Stored in `handshake_bindings.nonce`.
- Included in binding hash computation.
- Verified at verification time: if a nonce is provided by the verifier and it does not match the stored nonce, `nonce_mismatch` is added to reason codes.

**Properties**:
- Unique per binding (256 bits of randomness makes collision negligible).
- Not predictable (uses `crypto.randomBytes`, not `Math.random`).
- Not reusable (bound to a specific handshake via binding hash).

## 2. Expiry

**TTL**: Specified by `binding_ttl_ms` parameter at initiation. Clamped to `[60000ms, 1800000ms]` (1 minute to 30 minutes).

**Clamping code** (from `lib/handshake/create.js`):
```javascript
const clampedTtl = Math.max(60_000, Math.min(30 * 60_000, binding_ttl_ms));
const expires_at = new Date(now.getTime() + clampedTtl);
```

**Enforcement**:
- `checkBinding()` in `lib/handshake/bind.js`: `if (new Date(binding.expires_at) < new Date()) reason_codes.push('binding_expired')`.
- `checkNotExpired()` in `lib/handshake/invariants.js`: `if (new Date() >= expiresAt) return fail('BINDING_EXPIRED', ...)`.
- Expired bindings result in outcome `expired` at verification time.

**Properties**:
- Short-lived by design (max 30 minutes).
- Cannot be extended after initiation.
- Stored as ISO 8601 timestamp in `handshake_bindings.expires_at`.

## 3. Binding Hash

**Computation**: SHA-256 of the JSON-serialized canonical binding material with sorted keys.

**Canonical binding fields** (from `CANONICAL_BINDING_FIELDS` in `lib/handshake/invariants.js`):

```
action_type
resource_ref
policy_id
policy_version
policy_hash
interaction_id
party_set_hash
payload_hash
context_hash
nonce
expires_at
binding_material_version
```

**Derived hashes within binding material**:
- `party_set_hash`: `SHA-256(JSON.stringify(sorted ["role:entity_ref", ...]))`.
- `context_hash`: `SHA-256(JSON.stringify({action_type, resource_ref, intent_ref, policy_id, policy_version, interaction_id}, sorted_keys))`.
- `payload_hash`: `SHA-256(JSON.stringify(payload, sorted_keys))`.
- `policy_hash`: `SHA-256(JSON.stringify(policy.rules, sorted_keys))`.

**Integrity enforcement at initiation** (from `lib/handshake/create.js`):
- All `CANONICAL_BINDING_FIELDS` must be present: missing fields throw `BINDING_INVARIANT_VIOLATION`.
- No extra fields may be present: unexpected fields throw `BINDING_INVARIANT_VIOLATION`.

**Properties**:
- Content-addresses the exact action context.
- Any change to any field (action, parties, policy, payload, nonce, expiry) produces a different hash.
- Cannot be forged without knowing all input fields.

## 4. One-Time Consumption

**Mechanism**: Upon accepted verification outcome, the binding record is updated with `consumed_at`, `consumed_by`, and `consumed_for`.

**Enforcement** (from `lib/handshake/verify.js`):

```javascript
// Hard gate at top of _handleVerifyHandshake
if (existingBinding?.consumed_at) {
  return { result: { outcome: 'rejected', reason_codes: ['binding_already_consumed'], ... } };
}

// Consumption on accepted outcome
await supabase
  .from('handshake_bindings')
  .update({
    consumed_at: new Date().toISOString(),
    consumed_by: actorId,
    consumed_for: `handshake_verified:${handshake_id}`,
  })
  .eq('handshake_id', handshake_id)
  .is('consumed_at', null);  // <-- conditional: only if not already consumed
```

**Properties**:
- Two-phase check: hard gate (query) + conditional update (filter).
- The `.is('consumed_at', null)` filter makes the update a compare-and-swap operation.
- If two concurrent requests pass the hard gate, only one succeeds at the update level.

## 5. Idempotency

**Mechanism**: Content-addressed deduplication. `SHA-256(command.type + ":" + actor + ":" + JSON.stringify(input))` produces a deterministic key for each unique command.

**Cache**: In-memory `Map` with 10-minute TTL. If a command with the same idempotency key is received within the TTL, the cached result is returned with `_idempotent: true` flag.

**Additional dedup**: Handshake initiation supports an explicit `idempotency_key` parameter. If provided and a handshake with that key already exists, the existing handshake is returned instead of creating a duplicate.

**Properties**:
- Same command + same actor + same input = same key = same result.
- Prevents accidental duplicate submissions.
- Does not prevent intentionally different commands (different input = different key).

## 6. Downstream Action Coupling

**Mechanism**: The consumption record links the handshake to the downstream action that consumed it.

**Fields**:
- `consumed_by`: The entity that consumed the binding (actor ID).
- `consumed_for`: A structured reference to the downstream action (e.g., `handshake_verified:{handshake_id}`).

**Properties**:
- Creates a bidirectional link: handshake -> downstream action and (via query) downstream action -> handshake.
- Enables audit: for any downstream action, you can determine which handshake authorized it.
- Enables forensics: for any consumed handshake, you can determine what action it authorized.

## 7. Race Handling

**Scenario**: Two concurrent verification requests for the same handshake.

**Resolution**:

1. Both requests pass the initial `consumed_at` hard gate (both see `consumed_at IS NULL`).
2. Both requests process verification pipeline independently.
3. Both reach the consumption update step.
4. The update uses `.is('consumed_at', null)` filter.
5. First request: update succeeds, `consumed_at` is set.
6. Second request: update affects zero rows (filter no longer matches), consumption silently does not occur.
7. Database unique constraint on `handshake_consumptions` provides a secondary guard.

**Result**: Exactly one request consumes the binding. The other may have returned an accepted result but the binding was only consumed once. The downstream system must check consumption status before proceeding with the authorized action.
