# Protocol Weight

**Version:** 1.0
**Purpose:** Make EP's lightweightness measurable. Every claim in this document is auditable against the source code.

---

## 1. Critical Path Analysis

For each of the five core operations, this section counts the exact resources consumed on the hot path.

### 1.1 Initiate Handshake

**Function:** `initiateHandshake()` in `lib/handshake/create.js`

| Resource | Count | Detail |
|---|---|---|
| DB reads | 0-2 | 0 if no idempotency key; 1 for idempotency check; 1 for policy hash computation |
| DB writes | 3 | 1 handshake record, 1 batch party insert, 1 binding record |
| Hash computations | 5 | payload_hash (SHA-256), action_hash (SHA-256), party_set_hash (SHA-256), context_hash (SHA-256), binding_hash (SHA-256 of canonical material) |
| Policy lookups | 0-1 | 1 if policy_id provided (to compute policy_hash at bind time) |
| Crypto operations | 1 | nonce generation (32 bytes, `crypto.randomUUID`) |
| Event writes | 1 | `requireHandshakeEvent` (append-only, must succeed or operation fails) |

**Total DB round-trips (typical):** 4-5
**Total hash computations:** 5
**Estimated response payload:** ~800 bytes (handshake_id, binding, party records)

### 1.2 Present

**Function:** `addPresentation()` in `lib/handshake/present.js`

| Resource | Count | Detail |
|---|---|---|
| DB reads | 2-3 | 1 handshake status check, 1 party lookup, 0-1 authority registry lookup |
| DB writes | 1-2 | 1 presentation record, 0-1 handshake status update (initiated -> pending_verification) |
| Hash computations | 2 | presentation_hash (SHA-256 of presentation data), canonical_claims_hash (SHA-256 of normalized claims) |
| Authority lookups | 0-1 | 1 if issuer_ref provided (authority registry check) |
| Event writes | 1-2 | 1 presentation_added event, 0-1 status_changed event |

**Total DB round-trips (typical):** 4-5
**Total hash computations:** 2
**Estimated response payload:** ~600 bytes (presentation record)

### 1.3 Verify

**Function:** `verifyHandshake()` in `lib/handshake/verify.js`

| Resource | Count | Detail |
|---|---|---|
| DB reads | 4 | 1 binding consumed_at check, 1 handshake record, 3 parallel reads (parties, presentations, bindings) |
| DB writes | 3+N | 1 result record, 1 handshake status update, N party status updates, 0-1 binding consumption |
| Hash computations | 0-1 | 0-1 policy_hash recomputation (tamper detection) |
| Policy lookups | 0-1 | 1 if handshake has a policy_id |
| Event writes | 1 | verification outcome event |
| Pure checks | 6 | action_hash match, policy_hash match, binding expiry/nonce/payload, required presentations, assurance levels, issuer trust, delegation scope, policy claims |

**Total DB round-trips (typical):** 8+N (N = number of parties, typically 2)
**Total hash computations:** 0-1
**Estimated response payload:** ~400 bytes (outcome, reason_codes, assurance_achieved)

**Note:** Verify is the heaviest operation because it is the decision point. The N party status updates are sequential but could be batched in a future optimization. The parallel read of parties/presentations/bindings is already optimized via `Promise.all`.

### 1.4 Consume

**Function:** `consumeHandshake()` in `lib/handshake/consume.js`

| Resource | Count | Detail |
|---|---|---|
| DB reads | 1 | 1 handshake status check |
| DB writes | 2 | 1 consumption record (unique constraint enforces one-time use), 1 binding consumed_at update |
| Hash computations | 0 | None (binding_hash is provided by caller, not recomputed) |
| Event writes | 0 | No event (consumption is a DB-enforced invariant, not an event-sourced transition) |

**Total DB round-trips (typical):** 3
**Total hash computations:** 0
**Estimated response payload:** ~300 bytes (consumption record)

**Note:** Consume is the lightest operation by design. Its integrity guarantee comes from a database unique constraint, not application logic.

### 1.5 Create Policy

**Function:** `POST /api/policies` (currently read-only listing; policy creation via `handshake_policies` table)

| Resource | Count | Detail |
|---|---|---|
| DB reads | 0 | Policy listing reads from in-memory `TRUST_POLICIES` constant |
| DB writes | 1 | 1 policy record (when custom policies are persisted) |
| Hash computations | 0 | Policy hash is computed at handshake initiation, not at policy creation |
| Validation | 1 | `validatePolicyRules()` — structural schema check, pure function |

**Total DB round-trips (typical):** 0-1
**Total hash computations:** 0
**Estimated response payload:** ~200 bytes per policy

---

## 2. What Is NOT on the Hot Path

These operations are explicitly excluded from the critical path. They run asynchronously, on a schedule, or only when explicitly requested. They must never block trust-bearing operations.

| Operation | Trigger | Impact on Trust Path |
|---|---|---|
| `persistEvent()` in `canonical-writer.js` | Fire-and-forget after canonical writes | None. Event persistence is audit/observability. Failure does not block trust writes. |
| Trust score recomputation | After receipt submission or dispute resolution | None. Scores are materialized projections, not live computations on the trust path. |
| Blockchain anchoring (`lib/blockchain.js`) | Explicit call to `/api/blockchain/anchor` | None. Optional integrity proof. Never on the handshake hot path. |
| Feed generation (`/api/feed`) | User request | None. Reads materialized data. |
| Leaderboard computation (`/api/leaderboard`) | User request | None. Reads materialized data. |
| Sybil detection (`lib/sybil.js`) | During entity registration or score computation | None. Informational signal, not a trust gate. |
| Domain scoring (`lib/domain-scoring.js`) | User request to `/api/trust/domain-score` | None. Product feature built on canonical evaluator output. |
| ZK proof generation (`lib/zk-proofs.js`) | User request to `/api/trust/zk-proof` | None. Privacy feature, not trust path. |
| Attribution tracking (`lib/attribution.js`) | Receipt submission | None. Analytics, not trust state. |
| Auto-receipt configuration (`lib/auto-receipt-config.js`) | Configuration change | None. Product automation. |
| Cron expiry (`/api/cron/expire`) | Scheduled | Marks stale records. Does not produce trust decisions. |

---

## 3. Payload Size Budget

Typical payload sizes for the five core operations under normal conditions.

| Operation | Request Body | Response Body | Total Wire |
|---|---|---|---|
| Create Policy | ~500 bytes | ~200 bytes | ~700 bytes |
| Initiate Handshake | ~400 bytes | ~800 bytes | ~1.2 KB |
| Present | ~300 bytes | ~600 bytes | ~900 bytes |
| Verify | ~100 bytes | ~400 bytes | ~500 bytes |
| Consume | ~150 bytes | ~300 bytes | ~450 bytes |

**Full ceremony (initiate + 2 presents + verify + consume):** ~4.0 KB total wire transfer.

For comparison: a single OAuth2 token exchange is typically 2-4 KB. A SAML assertion is 5-15 KB. An EP trust ceremony produces a stronger guarantee (multi-party, policy-bound, one-time-use, auditable) in comparable bandwidth.

---

## 4. Computational Cost Summary

| Operation | DB Round-Trips | SHA-256 Hashes | Crypto Ops | Typical Latency* |
|---|---|---|---|---|
| Initiate | 4-5 | 5 | 1 (nonce) | 50-80ms |
| Present | 4-5 | 2 | 0 | 40-60ms |
| Verify | 8-10 | 0-1 | 0 | 80-120ms |
| Consume | 3 | 0 | 0 | 20-40ms |
| **Full ceremony** | **19-23** | **7-8** | **1** | **190-300ms** |

*Latency estimates assume a co-located PostgreSQL instance with <5ms round-trip. Actual latency depends on network topology and database load.

---

## 5. Invariants

These properties must hold for EP to claim lightweightness. Violations are bugs.

1. **No trust-path operation performs more than 10 DB round-trips** (except Verify, which scales with party count).
2. **No trust-path operation computes more than 6 hashes.**
3. **No trust-path operation makes external HTTP calls.** All trust state is local.
4. **Consume performs zero hash computations.** Integrity is enforced by the database, not application code.
5. **Event persistence never blocks trust-bearing writes** (except handshake events, which are mandatory for audit immutability).
6. **A full trust ceremony transfers less than 5 KB on the wire.**
7. **A full trust ceremony completes in under 500ms** on a co-located database.

If any of these invariants are violated by a code change, the change must either restore the invariant or update this document with justification.
