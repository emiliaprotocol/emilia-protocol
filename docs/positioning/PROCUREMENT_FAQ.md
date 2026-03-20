# EP Procurement FAQ

Answers to the ten questions that procurement, security, and risk teams ask when evaluating EMILIA Protocol.

---

## 1. What is the trust root?

The trust root is the **authority registry** -- a managed table of registered issuers, each identified by a unique `key_id`. When an entity presents credentials during a handshake, the credential's `issuer_ref` is resolved against this registry. Trust is granted only if the issuer is found, currently valid (not revoked, not expired, not before its validity start), and matches the expected authority for the policy's requirements.

The trust root is not a single key or certificate. It is a registry of issuer records, each with lifecycle states (valid, revoked, expired, not-yet-valid). The registry is managed as a trust table subject to write discipline (Invariant 1) -- it cannot be modified through direct database access from application routes.

**Key property**: Trust is fail-closed. If an issuer cannot be resolved, the default is `issuerTrusted = false` with `issuerTrustReason = 'unknown'`. There is no implicit trust.

**Code references**: `lib/handshake/present.js` (authority resolution pipeline), `lib/handshake/invariants.js` (`checkIssuerTrusted()`, `checkAuthorityNotRevoked()`), `scripts/check-protocol-discipline.js` (`checkEmbeddedIssuerKeys()` CI guard).

---

## 2. How do you handle delegated authority?

Delegation is modeled explicitly in the handshake lifecycle. A delegate is a party role in the handshake, with the following constraints enforced:

- **Identity binding**: The delegate's `entity_ref` must match the authenticated actor (`DELEGATE_BINDING_VIOLATION` on mismatch). Enforced in `lib/handshake/create.js`.
- **Scope**: The delegation chain specifies a list of policy IDs the delegate may act under, or a `*` wildcard for unrestricted scope. Actions outside the granted scope are rejected with `delegation_out_of_scope`.
- **Expiry**: Delegation chains have an explicit expiry timestamp. Expired delegations are rejected with `delegation_expired`.
- **Verification**: `checkDelegation()` in `lib/handshake/bind.js` runs during handshake verification for delegated-mode handshakes, checking both scope and expiry.
- **Auditability**: The delegation chain is preserved in the handshake record and recorded in handshake events.

Delegation is not transitive by default. Each delegation grant is an explicit record.

---

## 3. How do you prevent replay?

Three independent mechanisms, all of which must pass:

1. **Nonce**: A 32-byte random hex value (`crypto.randomBytes(32).toString('hex')`) generated at binding creation. Stored in the binding record. Verified at handshake verification -- nonce mismatch produces `nonce_mismatch` rejection. Provides per-binding uniqueness. Source: `lib/handshake/invariants.js` (`newNonce()`).

2. **Expiry**: Binding TTL is configurable but clamped to [60s, 1800s]. `checkBinding()` in `lib/handshake/bind.js` rejects expired bindings. Expired bindings cannot be verified regardless of other factors.

3. **One-time consumption**: On accepted verification, the binding's `consumed_at` timestamp is set via a conditional update with `IS NULL` filter. This is a compare-and-swap: only unconsumed bindings can transition. A unique constraint on `handshake_consumptions` prevents duplicate consumption records at the database level. Source: `lib/handshake/verify.js` (`_handleVerifyHandshake()`).

Additionally, content-addressed idempotency keys (`SHA-256(command.type + actor + JSON.stringify(input))`) provide a 10-minute dedup window at the protocol write level.

---

## 4. Can a verified artifact be reused?

No. A verified handshake binding can authorize exactly one downstream action (Invariant 8).

Enforcement is three-layered:

- **Hard gate**: `_handleVerifyHandshake()` checks `consumed_at` at the top of the function. Already-consumed bindings are rejected immediately with `binding_already_consumed` before any further processing.
- **Conditional update**: The consumption update uses `.is('consumed_at', null)` as a filter. If two concurrent requests both pass the hard gate, the conditional update ensures only one succeeds (the other gets zero affected rows).
- **Database constraint**: A unique constraint on the `handshake_consumptions` table prevents duplicate consumption records.

The `handshake_consumptions` table is in the `TRUST_TABLES` list, so it cannot be written by route handlers -- only through the `protocolWrite()` pipeline.

---

## 5. What happens if policy resolution fails?

The handshake is **rejected**. There is no fallback to a default, permissive, or cached policy. Policy resolution is fail-closed (Invariant 7).

Specific failure modes:

| Failure | Reason Code | Result |
|---|---|---|
| `resolvePolicy()` throws an exception | `policy_load_failed` | Rejected |
| `resolvePolicy()` returns null (no matching policy) | `policy_not_found` | Rejected |
| Policy loads but hash differs from initiation-time hash | `policy_hash_mismatch` | Rejected |

The policy hash is computed as `SHA-256(JSON.stringify(policy.rules, sorted_keys))` at initiation and stored on the handshake record. At verification, the policy is re-loaded, re-hashed, and compared. This prevents policy drift -- rules modified between initiation and verification are detected.

**Code references**: `lib/handshake/policy.js` (`resolvePolicy()`), `lib/handshake/verify.js` (`_handleVerifyHandshake()`), `lib/handshake/create.js` (hash computation at initiation).

---

## 6. What are the terminal states?

Handshake terminal states (no further transitions allowed):

| Terminal State | Meaning |
|---|---|
| `verified` (with `accepted` outcome) | Handshake passed all checks. Binding is eligible for one-time consumption. |
| `verified` (with `rejected` outcome) | Handshake failed one or more checks. Reason codes specify which checks failed. Binding is not consumable. |
| `expired` | Binding TTL elapsed before verification. No longer eligible for verification. |
| `revoked` | Handshake was explicitly revoked by an authorized actor. |
| `finalized` | Post-verification finalization completed. |

Dispute terminal states:

| Terminal State | Meaning |
|---|---|
| `resolved` | Dispute adjudicated. |
| `appeal_resolved` | Appeal adjudicated. |
| `withdrawn` | Dispute withdrawn by filer. |

All state transitions are recorded in handshake events and protocol events before the state change is materialized.

---

## 7. How are events reconstructed?

EP maintains two append-only event tables:

**`protocol_events`**: Covers all 17 command types across all aggregate types (receipt, commit, dispute, report, handshake). Each event records:
- `event_id` (UUID)
- `aggregate_type` and `aggregate_id` (the object that changed)
- `command_type` (what operation was performed)
- `parent_event_hash` (chain integrity)
- `payload_hash` (content-addressed payload)
- `actor_authority_id` (who performed the action)
- `idempotency_key` (dedup reference)
- `created_at` (timestamp)

**`handshake_events`**: Covers handshake lifecycle transitions. Each event records:
- `event_id`, `handshake_id`, `event_type` (initiated, presentation_added, status_changed, verified, rejected, expired, revoked)
- `actor_entity_ref`, `detail` (structured JSON), `created_at`

Reconstruction process:
1. Query events by `aggregate_id` to retrieve the full event sequence for any object.
2. Events are ordered by `created_at` and can be verified via `parent_event_hash` chain.
3. `scripts/replay-protocol.js` supports programmatic event replay for forensic analysis.
4. Database triggers prevent UPDATE and DELETE on both event tables, ensuring the event log is tamper-evident within the database layer.

---

## 8. How do you isolate tenants?

EP enforces tenant isolation through several mechanisms:

- **Entity references**: All actors, parties, and authorities are identified by entity references that are scoped to the tenant context established by the authentication layer.
- **Handshake party binding**: Handshake parties must have `entity_ref` matching the authenticated entity. An entity from one tenant context cannot participate as a party in another tenant's handshake (enforced by `ROLE_SPOOFING` and `INITIATOR_BINDING_VIOLATION` checks).
- **Authority registry scoping**: Authority records are managed per tenant context. An issuer registered in one tenant context is not automatically trusted in another.
- **Write discipline**: All trust-table writes go through `protocolWrite()`, which enforces actor identity from the authentication middleware. The authentication middleware establishes the tenant context.
- **Event isolation**: Protocol events and handshake events record the actor's authority context, enabling tenant-scoped queries and exports.

Tenant isolation is enforced at the protocol layer, not just the database layer. Even if database-level row-level security were bypassed, the actor-party binding checks in the handshake lifecycle would reject cross-tenant operations.

---

## 9. How do you prove operators cannot bypass controls?

Three-layer enforcement with runtime, build-time, and architectural guarantees:

### Runtime (lib/write-guard.js)

`getGuardedClient()` returns a Proxy that intercepts `insert()`, `update()`, `upsert()`, and `delete()` calls on all 13 trust tables. Any direct mutation attempt throws `WRITE_DISCIPLINE_VIOLATION`. All route handlers receive the guarded client, not the unguarded service client.

### Build-time (CI guards)

- `scripts/check-write-discipline.js`: Scans route files for imports of forbidden canonical functions and `getServiceClient` usage. Build fails (exit code 1) on violation, with a report listing file, line, and forbidden import.
- `scripts/check-protocol-discipline.js`: Scans all application and library files for `.from('trust_table').insert()` patterns outside the allowlisted canonical write layer. Also detects embedded issuer key patterns.

### Architectural

- `protocolWrite()` is the single choke point for all trust-changing writes. It enforces invariant checking, schema validation, authority resolution, abuse detection, idempotency, event persistence, and telemetry for every command.
- Event-before-state ordering ensures that bypassing `protocolWrite()` would also bypass event logging, making the bypass detectable through missing events.

### Evidence for auditors

- CI logs showing guard script execution on every build
- Runtime guard configuration (list of protected tables, list of blocked operations)
- Conformance test results: 47 invariant tests and 24 adversarial tests run as part of the test suite

---

## 10. What evidence can be exported for audits?

EP produces the following audit evidence natively:

| Evidence Type | Content | Source |
|---|---|---|
| **Protocol event exports** | Every trust-changing transition: actor, authority, command type, aggregate, payload hash, parent event hash, timestamp | `protocol_events` table |
| **Handshake event timeline** | Full handshake lifecycle: initiation, presentations, verification/rejection, consumption, revocation | `handshake_events` table |
| **Binding material** | Complete action context (action type, resource ref, policy, parties, payload, nonce, expiry) with computed hash | Handshake binding records |
| **Verification results** | Outcome (accepted/rejected), reason codes, verification timestamp, verifier identity | `handshake_results` table |
| **Consumption proof** | One-time-use evidence: consumption timestamp, consuming actor, binding reference | `handshake_consumptions` table |
| **Policy snapshots** | Policy rules version and hash at bind time, enabling point-in-time policy reconstruction | `handshake_policies` table, policy hash on handshake record |
| **Authority registry state** | Issuer lifecycle: registration, status changes, revocations | `authorities` table |
| **Write-path enforcement evidence** | CI guard execution logs, runtime guard configuration, violation reports | CI build logs, `lib/write-guard.js` configuration |
| **Conformance test results** | 47 invariant tests validating all 10 conformance invariants; 24 adversarial tests covering all 10 threat model entries | Test suite execution reports |

All event data is append-only (database triggers prevent UPDATE/DELETE). Binding material can be recomputed and compared against stored hashes for integrity verification. Events can be replayed using `scripts/replay-protocol.js` for forensic analysis.
