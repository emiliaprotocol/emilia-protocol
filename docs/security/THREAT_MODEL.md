# EMILIA Protocol -- Threat Model

## Scope

This threat model covers attacks against the trust enforcement layer of EMILIA Protocol. It does not cover infrastructure-level threats (network, OS, cloud provider) or application-level threats outside the trust subsystem (XSS, CSRF, etc.).

Each threat is listed with its attack vector, mitigation mechanism, and the code that enforces the mitigation.

---

## 1. Role Spoofing

**Threat**: An authenticated entity submits a presentation on behalf of a different party, impersonating them in a handshake.

**Mitigation**: Actor-party binding enforcement. When a presentation is added, the authenticated entity's ID is compared against the party's `entity_ref`. Mismatch throws `ROLE_SPOOFING` (HTTP 403).

**Enforcement**:
- `lib/handshake/present.js` (`_handleAddPresentation`): `if (party.entity_ref !== authenticatedEntity) throw HandshakeError('...', 403, 'ROLE_SPOOFING')`
- `lib/handshake/create.js` (`initiateHandshake`): Initiator party's `entity_ref` must match actor (`INITIATOR_BINDING_VIOLATION`). In delegated mode, delegate's `entity_ref` must match actor (`DELEGATE_BINDING_VIOLATION`).
- `lib/handshake/invariants.js` (`checkNoRoleSpoofing`): Pure invariant function that checks entity_ref match.

**Exception**: The `system` actor bypasses actor-party binding checks.

---

## 2. Issuer Spoofing

**Threat**: A presentation claims to be issued by a trusted authority but the issuer is not actually trusted, or has been revoked.

**Mitigation**: Authority resolution from a trusted registry. Issuer trust is resolved by looking up `issuer_ref` against the `authorities` table by `key_id`. Keys are never trusted from the presentation payload itself.

**Enforcement**:
- `lib/handshake/present.js` (`_handleAddPresentation`): Full issuer resolution pipeline with explicit status tracking (`authority_valid`, `authority_revoked`, `authority_not_found`, `authority_expired`, `authority_not_yet_valid`).
- `lib/handshake/invariants.js` (`checkIssuerTrusted`, `checkAuthorityNotRevoked`): Pure invariant functions.
- `scripts/check-protocol-discipline.js` (`checkEmbeddedIssuerKeys`): CI guard that detects `presentation.publicKey`, `presentation.signingKey`, `payload.key` patterns.

**Default**: Unknown issuers are untrusted (fail-closed). `issuerTrusted = false` is the default before resolution.

---

## 3. Policy Drift

**Threat**: Policy rules are modified between handshake initiation and verification, allowing weakened requirements to be applied retroactively.

**Mitigation**: Policy hash pinned at bind time. At initiation, `SHA-256(JSON.stringify(policy.rules, sorted_keys))` is computed and stored as `policy_hash` on the handshake. At verification, the policy is re-loaded, re-hashed, and compared.

**Enforcement**:
- `lib/handshake/create.js` (`_handleInitiateHandshake`): Computes and stores `policy_hash`.
- `lib/handshake/verify.js` (`_handleVerifyHandshake`): Re-computes hash, adds `policy_hash_mismatch` to reason codes if different.

**Failure mode**: Hash mismatch results in handshake rejection. There is no "accept with warning" path.

---

## 4. Artifact Replay

**Threat**: A previously valid handshake binding is replayed to authorize a second action.

**Mitigation**: Three-layer defense: nonce + expiry + one-time consumption.

**Enforcement**:
- **Nonce**: `crypto.randomBytes(32).toString('hex')` generated at initiation (`lib/handshake/invariants.js`, `newNonce()`). Stored in binding. Verified at verification time (nonce mismatch = rejection).
- **Expiry**: Binding TTL clamped to [60s, 1800s] at initiation. `checkBinding()` in `lib/handshake/bind.js` rejects expired bindings.
- **Consumption**: On accepted outcome, `consumed_at` is set with `IS NULL` filter on update. `_handleVerifyHandshake()` has a hard gate at the top that rejects already-consumed bindings before any processing.

---

## 5. Approval Reuse

**Threat**: A handshake result is consumed multiple times, authorizing multiple actions from a single verification.

**Mitigation**: `handshake_consumptions` table with a unique constraint. The binding consumption update uses `consumed_at IS NULL` as a filter condition, ensuring only unconsumed bindings can transition.

**Enforcement**:
- `lib/handshake/verify.js` (`_handleVerifyHandshake`): Hard gate checks `consumed_at` before any processing. Binding update uses `.is('consumed_at', null)` filter.
- `lib/write-guard.js`: `handshake_consumptions` is in `TRUST_TABLES`, preventing direct writes from routes.
- Database: Unique constraint on consumption records prevents duplicate entries.

**Race handling**: If two concurrent verification requests both pass the initial check, the `consumed_at IS NULL` update filter ensures only one succeeds. The other gets zero affected rows and the consumption is not recorded.

---

## 6. Direct Route Bypass

**Threat**: A route handler writes directly to trust tables, bypassing `protocolWrite()` and its validation, authorization, event logging, and idempotency guarantees.

**Mitigation**: Three-layer enforcement.

**Enforcement**:
- **Runtime**: `lib/write-guard.js` (`getGuardedClient()`): Proxy blocks `insert()`, `update()`, `upsert()`, `delete()` on all 13 trust tables. Throws `WRITE_DISCIPLINE_VIOLATION`.
- **CI (imports)**: `scripts/check-write-discipline.js`: Scans route files for forbidden canonical function imports and `getServiceClient` usage.
- **CI (patterns)**: `scripts/check-protocol-discipline.js`: Scans all files for `.from('trust_table').insert()` patterns outside allowlisted files.

---

## 7. Stale Trust Root

**Threat**: A handshake proceeds with a policy that no longer exists or cannot be loaded, potentially with no trust requirements enforced.

**Mitigation**: Policy resolution is fail-closed. If policy cannot be loaded at verification time, the handshake is rejected.

**Enforcement**:
- `lib/handshake/verify.js` (`_handleVerifyHandshake`): If `resolvePolicy()` throws, adds `policy_load_failed`. If it returns null, adds `policy_not_found`. Either results in rejection.
- `lib/handshake/policy.js` (`resolvePolicy`): Returns null if no identifiers match.

---

## 8. Ambiguous Delegation

**Threat**: A delegate acts beyond their authorized scope or after their delegation has expired.

**Mitigation**: Delegation model with explicit grants. Delegates must have a `delegation_chain` that specifies scope (list of policy IDs or `*` wildcard) and expiry.

**Enforcement**:
- `lib/handshake/bind.js` (`checkDelegation`): Checks delegation expiry and scope. Produces `delegation_expired` or `delegation_out_of_scope` reason codes.
- `lib/handshake/create.js` (`initiateHandshake`): In delegated mode, delegate's `entity_ref` must match the authenticated actor.
- `lib/handshake/verify.js` (`_handleVerifyHandshake`): Runs `checkDelegation()` for delegated-mode handshakes.

---

## 9. Event Omission

**Threat**: A trust-changing state transition occurs without a corresponding event being logged, creating an invisible action with no audit trail.

**Mitigation**: `requireHandshakeEvent()` throws on failure. `appendProtocolEvent()` throws on failure. Both are called before the state change is materialized.

**Enforcement**:
- `lib/handshake/events.js` (`requireHandshakeEvent`): Throws `EVENT_WRITE_REQUIRED` with handshake ID and event type. Used by all handshake lifecycle functions (`create`, `present`, `verify`, `finalize`).
- `lib/protocol-write.js` (`appendProtocolEvent`): Throws `ProtocolWriteError` with code `EVENT_PERSISTENCE_FAILED`. Called for every command type.
- Event-first ordering: Events are written before state changes. If event write fails, state change does not proceed.

---

## 10. Race-Condition Double Use

**Threat**: Two concurrent requests both verify the same handshake, each consuming the binding and authorizing separate actions.

**Mitigation**: Database-level unique constraint on consumption, plus conditional update filter.

**Enforcement**:
- `lib/handshake/verify.js` (`_handleVerifyHandshake`): Hard gate at top queries `consumed_at` before processing. Binding consumption update uses `.is('consumed_at', null)` filter, making it a conditional write that only succeeds if the binding has not been consumed.
- Database: Unique constraint on `handshake_consumptions` prevents duplicate consumption records.
- If the conditional update affects zero rows (because another request consumed it first), the consumption silently fails and the binding remains consumed by the first request only.
