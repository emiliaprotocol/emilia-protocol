# EP Naming Canonical Reference

> In the harshest systems, one thing has one name.

This document is the definitive naming reference for the Emilia Protocol. Every
protocol term has ONE canonical name. Where aliases exist, they are documented
with their reason, scope, and deprecation status.

**Rule**: If a term is not in this document, it is not a protocol term. If two
terms appear to mean the same thing, this document settles which is canonical.

---

## 1. Identity

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `entity_id` | string (UUID or slug) | The primary identifier for a registered entity in the EP registry. UUID in the `entities` table PK (`id`), human-readable slug in `entities.entity_id`. | DB: `entities.entity_id`, `receipts.entity_id`; API: all endpoints |
| `entity_ref` | string | A stable reference to an entity within a handshake context. Used where the identifier may be a slug, UUID, or external reference not guaranteed to exist in the local `entities` table. | DB: `handshake_parties.entity_ref`; Code: `party.entity_ref` |
| `principal_id` | string | An EP-IX identity principal. A principal is a cryptographic identity anchor that may span multiple entities or systems. Distinct from `entity_id` (which is a registry entry). | DB: `principals.principal_id`; API: `/api/identity/principal/{principalId}` |
| `actor` | string or object | The authenticated caller performing a protocol write. Resolved to a string for storage. Not a stable identifier -- use `actor_entity_ref` for durable audit references. | Code: `command.actor`; runtime only |
| `actor_entity_ref` | string | The resolved, stable entity reference of the actor that triggered an event. Stored on audit records. This is the durable form of `actor`. | DB: `handshake_events.actor_entity_ref`, `handshake_presentations.actor_entity_ref`, `handshake_consumptions.actor_entity_ref` |
| `actor_id` | string | **ALIAS for `actor_entity_ref`** in the `audit_events` table and `handshake_events` (legacy). See alias table below. | DB: `audit_events.actor_id` (legacy schema) |

### Identity Alias Resolution

| Alias | Canonical Term | Context | Reason | Status |
|---|---|---|---|---|
| `actor_id` | `actor_entity_ref` | `audit_events` table, `handshake_events` (pre-migration 041) | Legacy schema predates the `actor_entity_ref` convention. Migration 041 added `actor_entity_ref` to `handshake_events`. The `audit_events` table (migration 019) still uses `actor_id`. | **LEGACY** -- `audit_events.actor_id` is frozen in the schema. New tables use `actor_entity_ref`. |
| `actorRef` | `actor_entity_ref` | JavaScript variable in `consume.js`, `present.js` | Local variable name for the resolved string. Not a protocol term. | N/A (code-local) |

---

## 2. Authority & Trust

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `key_id` | string | The unique identifier of a registered authority in the `authorities` table. An authority is a trusted signer whose key_id can be referenced by presentations. | DB: `authorities.key_id` |
| `issuer_ref` | string | A reference to the authority that issued a credential presented during a handshake. Resolved against `authorities.key_id` during verification. | DB: `handshake_presentations.issuer_ref`; Code: `presentation.issuer_ref` |
| `issuer_status` | enum string | Explicit trust reason recorded on a presentation: why the issuer was trusted or untrusted (`self_asserted`, `authority_valid`, `authority_not_found`, `authority_revoked`, `authority_expired`, `authority_not_yet_valid`, `authority_table_missing`). | DB: `handshake_presentations.issuer_status` |
| `assurance_level` | enum string | The trust assurance tier: `low`, `medium`, `substantial`, `high`. Ranked ordinally (low=1, medium=2, substantial=3, high=4). Assigned per-party; policies can mandate minimum levels. | DB: `handshake_parties.assurance_level`; Code: `ASSURANCE_RANK` |
| `emilia_score` | number | The computed trust score for an entity based on receipt evidence. Stored on the entity record. | DB: `entities.emilia_score` |
| `confidence` | string | The qualitative trust confidence level derived from evidence evaluation (`pending`, `low`, `medium`, `high`). Distinct from `assurance_level` (which is a policy-mandated tier, not a computed output). | API: `TrustDecision.confidence` |

### Authority Alias Resolution

| Alias | Canonical Term | Context | Reason | Status |
|---|---|---|---|---|
| `issuer_ref` vs `key_id` | **These are NOT aliases.** | -- | `issuer_ref` is the presentation's claim about who issued it. `key_id` is the authority registry's identifier. Verification joins them: `authorities.find(a => a.key_id === presentation.issuer_ref)`. They are two sides of a lookup, not two names for the same field. | N/A -- distinct concepts |

---

## 3. Binding

This is the most terminology-dense area of the protocol. Every term is precisely
scoped.

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `binding_hash` | string (hex SHA-256) | The SHA-256 hash of the canonicalized binding material object. This is the tamper-evident seal over the entire binding envelope. Computed by `hashBinding()` in `lib/handshake/binding.js`. | DB: `handshake_bindings.binding_hash`, `handshake_results.binding_hash`; Code: `binding.js` |
| `action_hash` | string (hex SHA-256) | The SHA-256 hash of the canonical action intent triple: `{action_type, resource_ref, intent_ref}`. Computed at handshake initiation. Used at the trust gate to detect action intent tampering between initiation and gate evaluation. **Distinct from `binding_hash`**: `action_hash` covers only the action intent; `binding_hash` covers the entire binding envelope (which includes action context plus policy, parties, payload, nonce, expiry). | DB: `handshakes.action_hash`; Code: `create.js`, `gate/route.js` |
| `context_hash` | string (hex SHA-256) | The SHA-256 hash of the action context object: `{action_type, resource_ref, intent_ref, policy_id, policy_version, interaction_id}`. A component WITHIN the binding material -- it is one of the `CANONICAL_BINDING_FIELDS` that feeds into `binding_hash`. **Distinct from both `action_hash` and `binding_hash`**: `context_hash` is broader than `action_hash` (adds policy and interaction) but narrower than `binding_hash` (omits parties, payload, nonce, expiry). | DB: `handshake_bindings.context_hash`; Code: `binding.js computeContextHash()` |
| `policy_hash` | string (hex SHA-256) | The SHA-256 hash of `policy.rules` at initiation time. Stored on both the handshake record and the binding material. Detects policy modification between initiation and verification. | DB: `handshakes.policy_hash`, `handshake_results.policy_hash`; Code: `binding.js computePolicyHash()` |
| `party_set_hash` | string (hex SHA-256) | The SHA-256 hash of sorted `role:entity_ref` pairs. Captures the exact party set at bind time. | DB: `handshake_bindings.party_set_hash`; Code: `binding.js computePartySetHash()` |
| `payload_hash` | string (hex SHA-256) | The SHA-256 hash of the canonicalized payload object. The payload is the application-level data being bound (e.g., transaction details). | DB: `handshake_bindings.payload_hash`; Code: `binding.js computePayloadHash()` |
| `presentation_hash` | string (hex SHA-256) | The SHA-256 hash of the canonicalized presentation claims. Ensures presentation integrity. **Not part of the binding material** -- it is stored on the presentation record, not in `CANONICAL_BINDING_FIELDS`. | DB: `handshake_presentations.presentation_hash` |
| `nonce` | string (64 hex chars) | A 32-byte cryptographically random value, unique per binding. Ensures binding uniqueness and replay resistance. | DB: `handshake_bindings.nonce`; also `commits.nonce` (separate context) |
| `binding_material_version` | integer | Version of the binding material schema. Currently `1`. Incrementing this is a breaking change that invalidates all unconsumed bindings. | Code: `invariants.js BINDING_MATERIAL_VERSION` |
| `CANONICAL_BINDING_FIELDS` | frozen array | The exhaustive, ordered list of fields included in `binding_hash` computation: `action_type`, `resource_ref`, `policy_id`, `policy_version`, `policy_hash`, `interaction_id`, `party_set_hash`, `payload_hash`, `context_hash`, `nonce`, `expires_at`, `binding_material_version`. | Code: `invariants.js` |

### Binding Hash Hierarchy (Clarification)

These three hashes are **not aliases**. They form a containment hierarchy:

```
action_hash = SHA-256({action_type, resource_ref, intent_ref})
    |
    v  (subset of)
context_hash = SHA-256({action_type, resource_ref, intent_ref, policy_id, policy_version, interaction_id})
    |
    v  (one field within)
binding_hash = SHA-256(canonicalize({
    action_type, resource_ref, policy_id, policy_version, policy_hash,
    interaction_id, party_set_hash, payload_hash, context_hash,
    nonce, expires_at, binding_material_version
}))
```

**Why all three exist**: `action_hash` enables fast tamper detection at the trust
gate without recomputing the full binding. `context_hash` groups action + policy
context for the binding envelope. `binding_hash` is the complete cryptographic
seal.

---

## 4. Action & Resource

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `action_type` | enum string | The type of action being authorized: `install`, `connect`, `delegate`, `transact`. This is the **canonical internal name**. | DB: `handshakes.action_type`; Code: all handshake modules; API: `/api/commits` request body |
| `action` | string | **ALIAS for `action_type`** at the trust gate API boundary only. The `/api/trust/gate` endpoint accepts `action` in the request body and maps it to `action_type` internally. | API: `/api/trust/gate` request body field |
| `resource_ref` | string or null | The canonical name for the resource a handshake action targets. A freeform string identifying the specific resource (e.g., `"service-xyz"`, `"api-endpoint-123"`). Optional -- null means the handshake is not bound to a specific resource. | DB: `handshakes.resource_ref`; Code: all handshake modules; `CANONICAL_BINDING_FIELDS` |
| `intent_ref` | string or null | An optional reference to the caller's intent or purpose. Distinct from `action_type` (what KIND of action) and `resource_ref` (what resource). `intent_ref` captures WHY the action is being taken (e.g., an intent ID from an upstream workflow). Included in `action_hash` and `context_hash` but is NOT a standalone binding field in `CANONICAL_BINDING_FIELDS` -- it flows into `context_hash`. | DB: `handshakes.intent_ref`; Code: `create.js`, `gate/route.js` |
| `transaction_type` | enum string | The type of receipt transaction: `purchase`, `service`, `task_completion`, `delivery`, `return`, plus software-specific types. **This is a receipt-layer concept, NOT a handshake concept.** Completely unrelated to `action_type`. | DB: `receipts.transaction_type`; API: receipt submission |
| `transaction_ref` | string | The external transaction reference for a receipt. An idempotency key for receipt deduplication. **Not related to handshake binding.** | DB: `receipts.transaction_ref` |
| `transaction_hash` | string | The blockchain anchor transaction hash. **A blockchain concept, not a protocol binding concept.** | DB: `zk_batch_anchors.transaction_hash` |

### Action & Resource Alias Resolution

| Alias | Canonical Term | Context | Reason | Status |
|---|---|---|---|---|
| `action` | `action_type` | `/api/trust/gate` request body | API ergonomics -- the gate endpoint uses the shorter `action` in its public interface. Internally, the gate maps `action` to `action_type` when computing `action_hash` and matching against `handshakes.action_type`. | **ACTIVE ALIAS** -- documented, intentional. The API field is `action`; the protocol field is `action_type`. |
| `target_ref` | `resource_ref` | External documentation / comments only | The comment in `binding.js` line 21 reads: `target → resource_ref (aliased as target_ref externally)`. However, **`target_ref` does not appear in any code, database column, API parameter, or test**. It exists only in two JSDoc comments in `binding.js`. The canonical name is `resource_ref` everywhere. `target_ref` is a conceptual alias that was never materialized. | **PHANTOM ALIAS** -- exists only in comments. `target_ref` is not a real protocol term. The comments should be updated to remove this phantom alias, but no code change is needed. |

---

## 5. Consumption

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `consumed_at` | timestamp | When the binding was consumed. Set on `handshake_bindings` AND `handshake_consumptions`. Once set, irreversible (enforced by DB trigger in migration 045). | DB: `handshake_bindings.consumed_at`, `handshake_consumptions.consumed_at` |
| `consumed_by` | string | The entity reference of who consumed the binding. Stored on `handshake_bindings`. | DB: `handshake_bindings.consumed_by` |
| `consumed_for` | string | A compound reference (`type:id`) describing what downstream artifact consumed the binding. Stored on `handshake_bindings`. Format: `"commit:epc_xxx"` or `"handshake_verified:uuid"`. | DB: `handshake_bindings.consumed_for` |
| `consumed_by_type` | string | The type of downstream artifact that consumed the handshake (e.g., `commit_issue`, `trust_gate`). Stored on `handshake_consumptions` (the dedicated consumption tracking table). | DB: `handshake_consumptions.consumed_by_type` |
| `consumed_by_id` | string | The ID of the downstream artifact. Stored on `handshake_consumptions`. | DB: `handshake_consumptions.consumed_by_id` |
| `consumed_by_action` | string or null | WHAT action the consumption is for. Added per LOCK 100 B.1. | DB: `handshake_consumptions.consumed_by_action` |

### Consumption Design Note

Consumption state is recorded in **two places** by design (belt-and-suspenders):
1. `handshake_bindings.consumed_at/consumed_by/consumed_for` -- flag on the binding itself for fast "is consumed?" checks.
2. `handshake_consumptions` table -- structured consumption record with `consumed_by_type`, `consumed_by_id`, `consumed_by_action` for audit granularity.

These are NOT aliases. They are dual-write for defense-in-depth.

---

## 6. Handshake Lifecycle

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `handshake_id` | UUID | Primary key of a handshake. | DB: `handshakes.handshake_id`; all related tables FK |
| `mode` | enum string | Handshake protocol mode: `basic`, `mutual`, `selective`, `delegated`. | DB: `handshakes.mode`; Code: `invariants.js HANDSHAKE_MODES` |
| `status` | enum string | Handshake lifecycle state: `initiated`, `pending_verification`, `verified`, `rejected`, `expired`, `revoked`. | DB: `handshakes.status`; Code: `invariants.js HANDSHAKE_STATUSES` |
| `outcome` | enum string | Verification result: `accepted`, `rejected`, `partial`, `expired`. **Distinct from `status`**: `outcome` is the result of a verification evaluation; `status` is the handshake lifecycle state. An `accepted` outcome transitions status to `verified`. A `rejected` outcome transitions status to `rejected`. | DB: `handshake_results.outcome`; Code: `verify.js` |
| `interaction_id` | string or null | Links a handshake to a subject interaction in the calling system. An external correlation ID. | DB: `handshakes.interaction_id`; `CANONICAL_BINDING_FIELDS` |
| `session_ref` | string or null | An optional session reference on the binding. Tracks which session created the binding. **Not in `CANONICAL_BINDING_FIELDS`** -- informational only, not part of the hash. | DB: `handshake_bindings.session_ref` |
| `idempotency_key` | string or null | Client-provided key for idempotent handshake initiation. If a handshake with the same key exists, it is returned instead of creating a duplicate. | DB: `handshakes.idempotency_key` |
| `delegation_id` | string | Identifier for a delegation record (agent acting on behalf of principal). | DB: `delegations.id`; API: `/api/trust/gate` request body |

### Lifecycle Terms That Are NOT Aliases

| Term A | Term B | Why They Are Distinct |
|---|---|---|
| `status` | `outcome` | `status` is the handshake's current lifecycle state (mutable: `initiated` -> `verified`). `outcome` is the immutable result of a single verification evaluation. A handshake has one `status` but could theoretically have multiple evaluation attempts before one succeeds. |
| `verified_at` | `evaluated_at` | `verified_at` is when the handshake status changed to `verified`. `evaluated_at` is when the result record was created. They may differ if verification processing takes time. |
| `initiated_at` | `created_at` | `initiated_at` is the protocol-level initiation timestamp. `created_at` is the database row creation timestamp. In practice they are set to the same value, but `initiated_at` is the protocol term; `created_at` is infrastructure. |
| `commit_ref` | `decision_ref` | `commit_ref` on the `handshakes` table references a downstream commit artifact. `decision_ref` on `handshakes` and `handshake_results` references a downstream decision artifact or revocation reason. Both are outbound references to different downstream systems. |

---

## 7. Commits

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `commit_id` | string | The unique identifier of a commit (prefixed `epc_`). This is the **canonical internal name**. | DB: `commits.commit_id`; API: `/api/commits/verify` request body |
| `commit_ref` | string | **ALIAS for `commit_id`** in contexts where the commit is referenced from another record (e.g., handshake -> commit linkage, trust gate response). | DB: `handshakes.commit_ref`; API: `TrustDecision.extensions.commit_ref` |
| `kid` | string | Key ID identifying which signing key produced the commit signature. References the `authorities` registry. Not to be confused with `key_id` on authorities -- same concept, abbreviated per JWK convention. | DB: `commits.kid`; API: `CommitResponse.kid` |

### Commit Alias Resolution

| Alias | Canonical Term | Context | Reason | Status |
|---|---|---|---|---|
| `commit_ref` | `commit_id` | `handshakes.commit_ref`, trust gate response | When a commit is referenced from another record, the FK/reference field is named `commit_ref` to distinguish the reference from the source table's PK. This is standard FK naming convention, not a semantic alias. | **INTENTIONAL** -- FK naming convention. `commit_id` is the PK; `commit_ref` is the FK/reference. |

---

## 8. Events

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `event_type` | string | The type of handshake lifecycle event: `initiated`, `presentation_added`, `status_changed`, `verified`, `rejected`, `expired`, `revoked`. | DB: `handshake_events.event_type` |
| `command_type` | string | The type of protocol write command: `ISSUE_COMMIT`, `VERIFY_COMMIT`, `REVOKE_COMMIT`, `INITIATE_HANDSHAKE`, `VERIFY_HANDSHAKE`, etc. **Distinct from `event_type`**: commands are inputs; events are outputs. | DB: `protocol_events.command_type` |
| `aggregate_type` | string | The type of aggregate a protocol event belongs to (e.g., `commit`, `handshake`, `receipt`). | DB: `protocol_events.aggregate_type` |
| `aggregate_id` | string | The ID of the specific aggregate instance (e.g., a commit_id or handshake_id). | DB: `protocol_events.aggregate_id` |

### Event vs Command Clarification

`event_type` and `command_type` are NOT aliases. They live in different tables
(`handshake_events` vs `protocol_events`) and represent different concepts:
- A **command** is an intent to change state (input).
- An **event** is a record that state changed (output).

---

## 9. Receipts & Scoring

| Canonical Name | Type | Exact Meaning | Where Used |
|---|---|---|---|
| `transaction_ref` | string | External transaction reference for receipt deduplication. Unique per (entity_id, submitted_by) pair. | DB: `receipts.transaction_ref` |
| `transaction_type` | enum string | Receipt transaction category: `purchase`, `service`, `task_completion`, `delivery`, `return`, plus software types. | DB: `receipts.transaction_type` |
| `submitted_by` | UUID | The entity that submitted the receipt (the counterparty attesting to the transaction). | DB: `receipts.submitted_by` |
| `composite_score` | number | The weighted composite score computed for a single receipt. | DB: `receipts.composite_score` |
| `submitter_score` | number | The submitter's `emilia_score` at time of receipt creation. Used as evidence weight. | DB: `receipts.submitter_score` |
| `emilia_score` | number | The aggregate trust score on an entity, recomputed after each receipt. | DB: `entities.emilia_score` |

---

## 10. Cross-Layer Term Disambiguation

These terms appear in multiple protocol layers with different meanings. They are
NOT aliases of each other.

| Term | Layer 1 | Layer 2 | Why They Differ |
|---|---|---|---|
| `policy_id` | Handshake: identifies which verification policy governs the handshake | Trust gate: `GATE_POLICIES` key (`strict`, `standard`, `permissive`) | Same field name, different policy registries. Handshake policies are in the `policies` table; gate policies are hardcoded tiers. |
| `nonce` | Handshake binding: 32-byte random for replay resistance | Commit: random value for commit uniqueness | Same concept (replay resistance), different scopes. A handshake nonce and a commit nonce are independent values. |
| `expires_at` | Handshake binding: binding TTL deadline | Commit: commit expiry | Same concept, different records. |
| `status` | Handshake: lifecycle state | Commit: `active`, `fulfilled`, `revoked`, `expired` | Same field name, different state machines. |
| `action_type` | Handshake: what action the handshake authorizes | Commit: what action the commit authorizes | Same concept, same enum values. The handshake `action_type` flows through to the commit `action_type` when a gate decision issues a commit. |
| `transaction_type` | Receipt layer: purchase/service/etc. | -- | Receipt-only concept. Has zero relationship to handshake `action_type` despite both containing "type". |
| `transaction_ref` | Receipt layer: external transaction ID | -- | Receipt-only concept. Has zero relationship to any handshake `_ref` field. |
| `transaction_hash` | Blockchain layer: on-chain anchor hash | -- | Blockchain-only concept. Not a protocol binding hash. |

---

## 11. Summary of All Known Aliases

| Alias | Canonical | Scope | Type | Action Required |
|---|---|---|---|---|
| `target_ref` | `resource_ref` | Comments in `binding.js` only | **PHANTOM** -- never materialized in code, DB, or API | Remove from comments to eliminate reviewer confusion |
| `action` | `action_type` | `/api/trust/gate` request body | **ACTIVE** -- intentional API ergonomic shorthand | Document at API boundary. No code change needed. |
| `actor_id` | `actor_entity_ref` | `audit_events` table | **LEGACY** -- frozen in schema | New tables must use `actor_entity_ref`. |
| `commit_ref` | `commit_id` | FK references from other tables | **INTENTIONAL** -- FK naming convention | No change needed. |
| `kid` | `key_id` | Commit signing context | **INTENTIONAL** -- JWK convention abbreviation | No change needed. |

**Total aliases: 5.** Of these, only `target_ref` is genuinely confusing (phantom
alias that exists nowhere except two comments). The rest are intentional,
scoped, and justified.

---

## 12. The `resource_ref` / `target_ref` Verdict

The reviewer specifically flagged `target_ref` vs `resource_ref`. The definitive
answer:

**`resource_ref` is the ONE canonical name.** It appears in:
- `CANONICAL_BINDING_FIELDS` (the protocol's source of truth)
- Database columns: `handshakes.resource_ref`
- All JavaScript code: `create.js`, `binding.js`, `schema.js`, `gate/route.js`
- All tests: `property-based.test.js`, `handshake-adversarial.test.js`
- All documentation: `HANDSHAKE.md`, `OVERVIEW.md`, `REPLAY_RESISTANCE.md`

**`target_ref` appears NOWHERE in code, database, API, or tests.** It exists
only in two comment lines in `binding.js`:
- Line 21: `target → resource_ref (aliased as target_ref externally)`
- Line 30: `@param {string|null} params.resource_ref - The target resource (target_ref).`

These comments are vestigial from an early design phase where the external API
was expected to use `target_ref`. That design was never implemented. The comments
should be cleaned up, but no code or schema change is needed because `target_ref`
was never a real thing.

---

## 13. The `intent_ref` / `action_type` Verdict

The reviewer asked whether `intent_ref` and `action_type` are the same concept.
They are not.

| Field | Answers | Example |
|---|---|---|
| `action_type` | **WHAT** kind of action? | `"transact"` |
| `resource_ref` | **WHAT** resource? | `"service-xyz"` |
| `intent_ref` | **WHY** this action? | `"workflow-step-42"`, `"user-request-abc"` |

Together they form the **action intent triple**: `{action_type, resource_ref,
intent_ref}`, which is hashed into `action_hash` for tamper detection.

`action_type` is an enum with fixed values (`install`, `connect`, `delegate`,
`transact`). `intent_ref` is a freeform string -- a correlation ID from the
calling system's workflow. They are orthogonal dimensions.

---

*This document was created to satisfy the reviewer requirement: "In the harshest
systems, one thing has one name." Every protocol term now has exactly one
canonical name, and every alias is accounted for.*
