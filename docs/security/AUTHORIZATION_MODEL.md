# EMILIA Protocol -- Authorization Model

## Scope

This document describes how EP determines whether an actor is authorized to perform an action. EP's authorization model differs fundamentally from traditional RBAC/ABAC systems: identity is derived from authentication context, authority is resolved from a registry chain, and roles are matched structurally rather than declared.

---

## 1. Design Principles

### 1.1 Identity From Auth, Never Request Body (Principle 4.1)

The actor's identity is always extracted from the authentication layer (session, token, API key resolution), never from the request payload. A request body claiming `"actor": "user-123"` is ignored; the authenticated entity is used instead.

**Enforcement**:
- `_handleAddPresentation()` in `lib/handshake/present.js`: Extracts `authenticatedEntity` from `command.actor` (set by the auth middleware), not from `command.input`.
- `initiateHandshake()` in `lib/handshake/create.js`: The `actor` parameter is passed by the calling route after authentication, not parsed from the request body.

This prevents identity injection attacks where a malicious payload attempts to act as a different entity.

### 1.2 Authority Is Resolved, Not Declared (Principle 4.2)

No entity can declare its own authority level. Authority is resolved by looking up the entity against the authority registry chain. A presentation claiming high assurance is meaningless unless the issuer is trusted and the authority is valid.

**Enforcement**:
- `_handleAddPresentation()`: `issuerTrusted` defaults to `false`. Trust is only set to `true` after successful registry lookup with valid status, valid-from, and valid-to checks.
- `checkIssuerTrusted()` in `lib/handshake/invariants.js`: Pure function that verifies `presentation.issuer_ref` exists in the provided authorities list.

---

## 2. Authority Chain Resolution

Authorization decisions follow a four-link chain. Every link must be valid for the action to be authorized.

```
Trust Root (authorities table)
  -> Issuer (key_id matched, status active, within validity window)
    -> Delegation (optional: delegation_chain with scope and expiry)
      -> Actor (authenticated entity bound to handshake party)
```

### 2.1 Trust Root

The `authorities` table contains registry entries keyed by `key_id`. See `TRUST_ROOTS.md` for lifecycle details.

### 2.2 Issuer Resolution

When a presentation includes an `issuer_ref`, the system queries `authorities` by `key_id`. The issuer must be:
- Found in the registry (`authority_not_found` = rejection).
- Status `active` (not `revoked`).
- Within `valid_from` / `valid_to` window.

Each condition is tracked with an explicit `issuerTrustReason` for auditability. The `ISSUER_STATUS_MAP` maps trust reasons to precise revocation vocabulary, ensuring `unknown` is never conflated with `revoked`.

### 2.3 Delegation

In `delegated` mode, the actor is not the principal but a delegate acting on behalf of the principal. The delegation chain specifies:
- `scope`: Array of policy IDs the delegate is authorized for, or `*` for wildcard.
- `expires_at`: Delegation expiry timestamp.

**Enforcement** (`checkDelegation()` in `lib/handshake/bind.js`):
- If `delegation_chain.expires_at` is in the past: `delegation_expired`.
- If `delegation_chain.scope` does not include the handshake's `policy_id` and is not `*`: `delegation_out_of_scope`.

### 2.4 Actor Binding

The final link binds the authenticated entity to a handshake party.

**Non-delegated mode**: `initiatorParty.entity_ref` must match `actorEntityId`. Mismatch throws `INITIATOR_BINDING_VIOLATION` (HTTP 403).

**Delegated mode**: `delegateParty.entity_ref` must match `actorEntityId`. Mismatch throws `DELEGATE_BINDING_VIOLATION` (HTTP 403).

**Presentation time**: `party.entity_ref` must match `authenticatedEntity`. Mismatch throws `ROLE_SPOOFING` (HTTP 403).

**System bypass**: The `system` actor is exempt from actor-party binding checks.

---

## 3. Role Resolution via Party Matching

EP does not maintain a role assignment table. Roles are structural: an entity's role in a handshake is determined by which party slot it occupies.

**Party roles**: `initiator`, `responder`, `verifier`, `delegate` (defined in `VALID_PARTY_ROLES`).

**Resolution**: When a handshake is initiated, each party is specified with a `role` and `entity_ref`. The entity does not "have" a role globally -- it has a role within this specific handshake context.

**Policy requirements**: Policy rules define `required_parties` by role. The system checks whether a presentation exists for each required role (`checkAllPartiesPresent()` in `lib/handshake/invariants.js`). The entity behind that role is validated through actor binding, not through a role membership lookup.

---

## 4. Presenter Validation

When an entity submits a presentation, two conditions must hold:

1. **Party existence**: A party with the claimed `party_role` must exist in the handshake's `handshake_parties` table.
2. **Entity match**: The party's `entity_ref` must match the authenticated entity (`command.actor`).

If condition 1 fails: `PARTY_NOT_FOUND` (HTTP 404).
If condition 2 fails: `ROLE_SPOOFING` (HTTP 403).

In delegated mode, a valid delegation chain allows the delegate to present on behalf of the principal, but the delegate's own `entity_ref` must still match the authenticated entity.

**Invariant**: `checkNoRoleSpoofing()` in `lib/handshake/invariants.js` encodes this as a pure function: `party.entity_ref !== authenticatedEntity` = failure.

---

## 5. Integration with Handshake Verification

Authorization is not a standalone gate -- it is woven into the handshake verification pipeline.

**At initiation**: Actor-party binding is enforced. Policy hash is pinned. Binding material is computed.

**At presentation**: Actor-party binding is re-enforced. Issuer trust is resolved from the registry. Revocation status is recorded.

**At verification**: All invariants run (`runAllInvariants()`):
- Binding validity (expiry, nonce, payload hash).
- All required parties present.
- All issuers trusted and not revoked.
- Assurance levels met.
- No duplicate or immutable results.

A handshake is accepted only if every invariant passes. There is no partial authorization.

---

## 6. Distinction from Traditional RBAC/ABAC

| Aspect | Traditional RBAC/ABAC | EP Authorization |
|---|---|---|
| Role assignment | Persistent role table | Structural: party slot in handshake |
| Authority source | Declared by admin or self | Resolved from registry chain |
| Identity source | Token claims or request body | Authentication layer only |
| Policy evaluation | Evaluate rules against attributes | Pin policy at initiation, re-verify at verification |
| Decision persistence | Access granted/denied per request | Binding with cryptographic hash, consumed once |
| Delegation | Role inheritance or assumption | Explicit delegation chain with scope and expiry |
| Fail mode | Often default-allow with fallback | Fail-closed at every link in the chain |

EP's model is action-scoped rather than session-scoped. Authorization is not a gate that opens once and stays open -- it is a binding that authorizes exactly one action and is consumed upon use.
