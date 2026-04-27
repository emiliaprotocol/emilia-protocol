# PIP-002: Handshake Extension

**Status:** Accepted  
**Type:** Extension  
**Created:** 2026-04-07  
**Author(s):** Iman Schrock  
**Requires:** PIP-001  

## Abstract

The Handshake extension adds pre-action trust enforcement to EP Core. A Handshake binds actor identity, authority, policy, action context, nonce, expiry, and one-time consumption into a replay-resistant authorization ceremony. No action executes without a verified Handshake when policy requires it.

## Specification

### Binding Material (frozen, versioned)

```
BINDING_MATERIAL_VERSION: 1

Canonical fields (sorted, hashed):
- action_type
- resource_ref
- intent_ref
- policy_hash
- party_set_hash
- nonce (32 bytes, crypto-random)
- expires_at (clamped 60s–1800s)
```

`binding_hash = SHA-256(canonicalize(binding_material))`

### Lifecycle

```
initiated → pending_verification → verified | rejected | expired | revoked
```

### Modes

- `basic`: One initiator, one verifier
- `mutual`: Both parties present credentials
- `selective`: Subset disclosure
- `delegated`: Agent acts on principal's authority

### Assurance Levels

`low < medium < substantial < high`

### Invariants (10 security properties)

1. Expiry enforcement
2. Party completeness
3. Binding validity
4. Issuer trust
5. Authority revocation check
6. Assurance level minimum
7. Duplicate prevention
8. Interaction binding
9. Role spoofing prevention
10. Result immutability

### One-Time Consumption

A Handshake is consumed exactly once via `consume_handshake_atomic()` RPC with `FOR UPDATE` lock. The unique constraint on `handshake_consumptions.handshake_id` provides the database-level guarantee.

## Reference Implementation

`lib/handshake/` — create.js, schema.js, invariants.js, consume.js
