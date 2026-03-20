# EMILIA Protocol -- Handshake Specification

## Definition

A Handshake is a cryptographically bound pre-action trust envelope that establishes identity, authority, and policy compliance for a specific action before that action executes.

Formally: `Handshake = (parties, presentations, binding, policy, result)` where:

- **parties** declare who is involved and in what role
- **presentations** prove identity claims for each party
- **binding** cryptographically pins the action context (nonce, expiry, hashes)
- **policy** defines what claims and assurance levels are required
- **result** records the verification outcome (accepted/rejected/partial/expired)

## What Handshake Is NOT

- **Not a login session.** A handshake is scoped to a single action, not a session. It is consumed upon use.
- **Not a wallet or key pair.** There are no embedded signing keys. Authority comes from a trusted registry, not from keys carried in presentations.
- **Not a social profile.** Handshakes do not represent persistent identity. They represent a one-time proof that specific trust requirements were met for a specific action.
- **Not a general-purpose identity assertion.** Handshakes bind to `action_type`, `resource_ref`, and `policy_id`. They cannot be reused for a different action.

## Lifecycle

```
initiated --> pending_verification --> verified --> consumed
                                   \-> rejected
                                   \-> expired
         \--------------------------------------------> revoked
```

### States

| State | Description | Transitions From | Transitions To |
|---|---|---|---|
| `initiated` | Handshake created with parties and binding. No presentations yet. | (creation) | `pending_verification`, `revoked` |
| `pending_verification` | At least one presentation has been added. Awaiting verification. | `initiated` | `verified`, `rejected`, `expired`, `revoked` |
| `verified` | All invariants passed. Handshake accepted. | `pending_verification` | `revoked` (consumed via binding) |
| `rejected` | One or more invariants failed. Terminal state. | `pending_verification` | (none) |
| `expired` | Binding TTL exceeded before verification. Terminal state. | `pending_verification` | (none) |
| `revoked` | Explicitly revoked by a party or system. Terminal state. | `initiated`, `pending_verification`, `verified` | (none) |

### State Transition Events

Every state transition emits a mandatory `handshake_events` record via `requireHandshakeEvent()` **before** the state change is materialized. If the event write fails, the state change does not proceed.

## Parties

Parties are declared at initiation time and stored in `handshake_parties`. Each party has:

| Field | Type | Description |
|---|---|---|
| `party_role` | enum | One of: `initiator`, `responder`, `verifier`, `delegate` |
| `entity_ref` | string | Reference to the authenticated entity |
| `assurance_level` | enum | Required level: `low`, `medium`, `substantial`, `high` |
| `verified_status` | string | Starts `pending`, becomes `verified`, `rejected`, or `expired` |
| `delegation_chain` | JSON | For delegates: scope, expiry, and chain of authority |

### Party Role Semantics

- **initiator**: The entity requesting the action. Must match the authenticated actor (enforced at creation: `INITIATOR_BINDING_VIOLATION`).
- **responder**: The counterparty. Required in `mutual` mode.
- **verifier**: An entity that independently verifies presentations.
- **delegate**: Acts on behalf of the initiator. Required in `delegated` mode. The delegate's `entity_ref` must match the authenticated actor (`DELEGATE_BINDING_VIOLATION`).

## Modes

| Mode | Required Parties | Semantics |
|---|---|---|
| `basic` | initiator | Single-party action authorization |
| `mutual` | initiator + responder | Both parties must present and verify |
| `selective` | initiator | Selective disclosure of claims |
| `delegated` | initiator + delegate | Delegate acts on behalf of initiator with scoped authority |

## Presentations

A presentation is an identity proof submitted by a party. Stored in `handshake_presentations`.

| Field | Type | Description |
|---|---|---|
| `party_role` | string | Which party role this presentation belongs to |
| `presentation_type` | string | Type of proof (e.g., credential type) |
| `issuer_ref` | string | Reference to the issuing authority's `key_id` |
| `presentation_hash` | string | SHA-256 of the raw presentation data |
| `disclosure_mode` | enum | `full`, `selective`, or `commitment` |
| `normalized_claims` | JSON | Canonicalized claims extracted from the presentation |
| `canonical_claims_hash` | string | Hash of normalized claims |
| `actor_entity_ref` | string | Authenticated entity that submitted this presentation |
| `authority_id` | string | Resolved authority ID from registry lookup |
| `issuer_status` | string | Trust determination: `authority_valid`, `authority_revoked`, `authority_not_found`, etc. |
| `verified` | boolean | Whether the issuer is trusted |
| `revocation_status` | string | `good`, `revoked`, `expired`, `not_yet_valid`, `unknown`, `not_applicable`, `registry_unavailable` |

### Actor-Party Binding

When a presentation is added, the authenticated entity must match the party's `entity_ref`. This is enforced in `_handleAddPresentation()`. Violation throws `ROLE_SPOOFING`. Exception: the `system` actor bypasses this check.

### Issuer Trust Resolution

Issuer trust is resolved at presentation time against the `authorities` table:

1. If no `issuer_ref`: self-asserted, trust deferred to policy.
2. If `issuer_ref` provided: look up `authorities` table by `key_id`.
   - Not found: `authority_not_found`, `verified = false`.
   - Found but `status = 'revoked'`: `authority_revoked`, `verified = false`.
   - Found but `valid_to < now`: `authority_expired`, `verified = false`.
   - Found but `valid_from > now`: `authority_not_yet_valid`, `verified = false`.
   - Found and valid: `authority_valid`, `verified = true`.

This is fail-closed: unknown issuers are never trusted.

## Verification

Verification is triggered via `verifyHandshake()` -> `protocolWrite(VERIFY_HANDSHAKE)` -> `_handleVerifyHandshake()`.

### Verification Pipeline

1. **Consumption gate**: Reject if binding already consumed (`consumed_at IS NOT NULL`).
2. **State gate**: Reject if handshake is not `initiated` or `pending_verification`.
3. **Action hash check**: If handshake has `action_hash`, provided hash must match.
4. **Policy hash check**: If handshake has `policy_hash`, provided hash must match.
5. **Binding checks** (`checkBinding()`): expiry, consumption, nonce presence, nonce match, payload hash match, payload hash required.
6. **Party presentation checks**: All required party roles must have presentations.
7. **Assurance level checks**: Each party's presentations must be verified.
8. **Issuer trust checks**: Revoked or unverified presentations are flagged.
9. **Delegation scope checks** (delegated mode): Delegation expiry and scope validation.
10. **Policy resolution**: Load policy by `policy_id`, re-hash rules, compare with stored `policy_hash`. Fail-closed if policy cannot be loaded.
11. **Policy claims checks**: Required claims per role must be present in normalized claims.
12. **Policy assurance checks**: Party assurance levels must meet policy minimums.

### Outcome Determination

| Outcome | Condition |
|---|---|
| `accepted` | Zero reason codes |
| `partial` | All reason codes are assurance/verification related only |
| `expired` | Reason codes include `binding_expired` |
| `rejected` | Any other failure reason code |

### Post-Verification

On `accepted` outcome:
- Binding is consumed: `consumed_at` set, `consumed_by` set to actor, `consumed_for` set to `handshake_verified:{handshake_id}`.
- Update filter `consumed_at IS NULL` ensures exactly-once consumption.

## Revocation

Any party to a handshake (or system) may revoke it. Revocation:
1. Verifies the actor is a party to the handshake.
2. Rejects if handshake is already `revoked` or `expired`.
3. Writes a mandatory event via `requireHandshakeEvent()`.
4. Updates status to `revoked` with `decision_ref` (reason) and `revoked_by`.

## Binding Material Specification

The binding envelope is defined by `CANONICAL_BINDING_FIELDS` in `lib/handshake/invariants.js`:

```
action_type          -- what action this handshake authorizes
resource_ref         -- what resource the action targets
policy_id            -- which policy governs this handshake
policy_version       -- pinned policy version
policy_hash          -- SHA-256 of policy.rules at initiation time
interaction_id       -- reference to the subject interaction
party_set_hash       -- SHA-256 of sorted "role:entity_ref" pairs
payload_hash         -- SHA-256 of canonicalized payload
context_hash         -- SHA-256 of action + policy + interaction context
nonce                -- 32-byte random hex, unique per binding
expires_at           -- binding TTL deadline
binding_material_version  -- version of the binding envelope schema (currently 1)
```

The `binding_hash` is computed as: `SHA-256(JSON.stringify(bindingMaterial, sorted_keys))`.

At initiation, the code asserts that:
- All `CANONICAL_BINDING_FIELDS` are present in the material (no missing fields).
- No extra fields exist in the material (envelope must be exact).

Violation of either throws `BINDING_INVARIANT_VIOLATION`.
