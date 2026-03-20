# EMILIA Protocol -- Policy Binding Specification

## Overview

Policy governs what trust requirements must be satisfied for a handshake to be accepted. Policy is versioned, hash-pinned at bind time, and fail-closed on resolution failure. This document specifies the exact semantics.

## Policy Structure

Policies are stored in the `handshake_policies` table. A policy record contains:

| Field | Type | Description |
|---|---|---|
| `policy_id` | UUID | Primary key |
| `policy_key` | string | Human-readable policy identifier |
| `version` | integer | Monotonically increasing version number |
| `status` | string | `active` or `inactive` |
| `rules` | JSON | The policy rules object |

### Policy Rules Schema

```json
{
  "required_parties": {
    "<role_name>": {
      "required_claims": ["claim_a", "claim_b"],
      "minimum_assurance": "low|medium|substantial|high"
    }
  },
  "binding": {
    "payload_hash_required": true,
    "nonce_required": true,
    "expiry_minutes": 10
  },
  "storage": {
    "store_raw_payload": true,
    "store_normalized_claims": true
  }
}
```

All three top-level keys (`required_parties`, `binding`, `storage`) are required. Validation is performed by `validatePolicyRules()` in `lib/handshake/policy.js`.

## Resolution Rules

Policy resolution is performed by `resolvePolicy()` in `lib/handshake/policy.js`. Resolution order:

1. **By `policy_id`** (most specific): Load by primary key via `loadPolicyById()`.
2. **By `policy_key` + `policy_version`**: Load by key and exact version.
3. **By `policy_key` only**: Load the latest active version (`status = 'active'`, ordered by `version DESC`, limit 1).
4. **No identifiers**: Returns `null`.

## Canonical Hashing

At handshake initiation, the policy's rules are hashed to produce a `policy_hash`:

```javascript
policy_hash = SHA-256(JSON.stringify(policy.rules, Object.keys(policy.rules).sort()))
```

This hash is:
- Stored on the `handshakes` record as `policy_hash`.
- Included in the canonical binding material.
- Re-computed at verification time and compared.

The key sorting in `JSON.stringify` ensures deterministic serialization regardless of property insertion order.

## Failure Modes

All failure modes result in rejection. There is no fallback or degraded acceptance.

### At Initiation

| Failure | Behavior |
|---|---|
| Policy cannot be loaded | `policy_hash` stored as `null`. Verification will detect this and may reject depending on verification-time policy availability. |
| Policy has no `rules` | `policy_hash` stored as `null`. |

### At Verification

| Failure | Reason Code | Behavior |
|---|---|---|
| Policy cannot be loaded (`resolvePolicy` throws) | `policy_load_failed` | Handshake rejected |
| Policy not found (returns null) | `policy_not_found` | Handshake rejected |
| Policy hash mismatch (rules changed since initiation) | `policy_hash_mismatch` | Handshake rejected |
| Provided `policy_hash` parameter does not match stored hash | `policy_hash_required` or `policy_hash_mismatch` | Handshake rejected |
| Required claims missing for a role | `policy_claims_missing_{role}` | Handshake rejected |
| Assurance level below policy minimum for a role | `policy_assurance_below_minimum_{role}` | Handshake outcome = `partial` |
| Policy rules malformed (fails validation) | Validation error thrown | Handshake rejected |

## Version Freeze Semantics

Once a handshake is initiated with a `policy_id` and `policy_hash`:

- The handshake is bound to the **exact version of the policy rules** that existed at initiation time.
- If the policy is updated (new version published), the handshake's `policy_hash` will not match the new rules, causing `policy_hash_mismatch` at verification.
- There is no concept of "latest" for an existing handshake. The policy is frozen at bind time.
- To use a new policy version, a new handshake must be initiated.

This prevents a class of attacks where policy is weakened between initiation and verification.

## Policy Claims Checking

`checkClaimsAgainstPolicy()` in `lib/handshake/policy.js` verifies that normalized claims satisfy policy requirements:

```javascript
function checkClaimsAgainstPolicy(normalizedClaims, policyRequirements) {
  // For each required_claim in policyRequirements.required_claims:
  //   If the claim is missing, undefined, or null in normalizedClaims: add to missing list
  // Returns { satisfied: boolean, missing: string[] }
}
```

Missing claims produce a `policy_claims_missing_{role}` reason code in the verification pipeline.

## Assurance Level Checking

Assurance levels have a defined rank order:

```
low: 1 < medium: 2 < substantial: 3 < high: 4
```

`checkAssuranceLevel()` in `lib/handshake/invariants.js` compares the achieved level against the required level. If `achieved_rank < required_rank`, the invariant fails with code `ASSURANCE_BELOW_MINIMUM`.

At verification time, if a party's assurance level is below the policy's `minimum_assurance` for that role, the reason code `policy_assurance_below_minimum_{role}` is added. This results in a `partial` outcome (not full rejection) if it is the only type of failure.
