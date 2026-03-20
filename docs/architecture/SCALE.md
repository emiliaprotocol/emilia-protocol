# EP Scale Architecture

Section 1 of the next-phase design. This document describes how the EMILIA Protocol
scales to 10M+ trust decisions per day while preserving its core invariants:
append-only evidence, one-time consumption, and cryptographic binding integrity.

---

## 1. Three Planes

EP separates concerns into three operational planes. Each has different consistency
requirements, latency budgets, and failure modes.

### Control Plane

Policy definitions, entity registration, delegation graphs, authority registry.
Changes are infrequent (minutes to hours) and can tolerate seconds of propagation
delay. Strong consistency: a policy change must be visible to all decision nodes
before it takes effect.

**Tables**: `entities`, `delegations`, `authority_registry`, `handshake_policies`

### Decision Plane

The hot path. Handshake creation, verification, and consumption. Commit issuance.
Every machine action that requires trust evaluation flows through here.
Latency-critical. Consistency: linearizable within a single handshake lifecycle;
eventually consistent across entity-level aggregates.

**Tables**: `handshakes`, `handshake_parties`, `handshake_bindings`,
`handshake_presentations`, `handshake_results`, `handshake_consumptions`, `commits`

### Evidence Plane

Receipts, protocol events, handshake events, score history. Append-only by design.
Tolerates higher write latency (100ms+) because evidence recording does not block
the decision. Must be durable: once acknowledged, evidence must never be lost.

**Tables**: `receipts`, `protocol_events`, `handshake_events`, `score_history`

---

## 2. Throughput Design Principles

### 2A. Narrow the Critical Path

A handshake-create operation must do the minimum work synchronously:

1. Validate input + idempotency check (index lookup)
2. Insert `handshakes` + `handshake_parties` + `handshake_bindings` (single transaction)
3. Return handshake_id + binding material

Everything else (event recording, score updates, analytics projection) happens
asynchronously. The critical path touches three tables in one transaction.

### 2B. Precompute Immutable Artifacts

Binding hashes, party set hashes, and policy snapshots are computed once at creation
time and stored. Verification never recomputes them -- it compares stored values.
This eliminates the most expensive CPU work from the read path.

### 2C. Split Reads and Writes

Write operations target the canonical OLTP store. Read-heavy operations (trust
profiles, entity dashboards, audit queries) target analytical projections that
are populated asynchronously. The scoring function (`compute_emilia_score`) reads
from a rolling window that can be materialized.

### 2D. Hot-Path Indexing

Migration `048_hot_path_indexes.sql` adds targeted indexes for the decision plane:

| Index | Table | Purpose |
|---|---|---|
| `idx_handshake_parties_handshake_role` | `handshake_parties` | Verification: find parties by handshake + role |
| `idx_bindings_consumed` | `handshake_bindings` | Partial index: consumed bindings only |
| `idx_bindings_unconsumed` | `handshake_bindings` | Partial index: available bindings only |
| `idx_commits_entity_status` | `commits` | Active commits per entity |
| `idx_receipts_entity_time` | `receipts` | Scoring window aggregation scans |

These are additive. No schema changes, no constraint modifications.

Pre-existing indexes confirmed sufficient:
- `idx_handshake_parties_entity` (035)
- `idx_handshake_consumptions_binding` (042)
- `idx_handshake_bindings_binding_hash` (042_binding_material)
- `idx_protocol_events_aggregate` (032)
- `idx_handshake_events_handshake_created` (037)
- `uq_handshakes_idempotency_key` (039)

---

## 3. Database Strategy

### 3A. Canonical OLTP Store

PostgreSQL (Supabase) remains the single source of truth. All writes go here.
Transactions are used for multi-table atomicity (handshake creation, consumption).
Advisory locks or SELECT FOR UPDATE protect against double-consume races.

### 3B. Analytical Projection

For read-heavy dashboards and trust profile queries, a separate read replica or
materialized view layer projects from the event store. The projection pipeline
consumes `protocol_events` and `handshake_events` to build:

- Entity trust profiles (aggregate scores, receipt counts, trend data)
- Handshake activity summaries (per-entity, per-policy)
- Audit timelines (full event replay for compliance)

Projection lag target: < 5 seconds under normal load, < 30 seconds under peak.

### 3C. Consistency Rules

| Operation | Consistency | Mechanism |
|---|---|---|
| Handshake create | Serializable within handshake | Single PG transaction |
| Consumption | Linearizable | UNIQUE constraint + SELECT FOR UPDATE |
| Score update | Eventually consistent | Async trigger / queue |
| Event append | Durable, ordered | Append-only table + sequence |
| Policy read | Read-your-writes | Control plane cache invalidation |

---

## 4. Queueing Boundaries

### Synchronous (in the request path)

- Idempotency check (index lookup, ~2ms)
- Handshake insert transaction (3 tables, ~15ms)
- Consumption with uniqueness enforcement (~10ms)
- Commit issuance (~12ms)

### Asynchronous (queued after response)

- Protocol event recording
- Handshake event recording
- Score recomputation
- Analytical projection updates
- Notification dispatch (webhooks, delegation alerts)
- Blockchain anchoring (batch, periodic)

The queue boundary sits immediately after the OLTP transaction commits. A
lightweight queue (pg_notify for low volume, dedicated queue for high volume)
delivers async work items. Failed async work is retried with exponential backoff;
it never blocks the decision path.

---

## 5. Multi-Region Design

### Phase 1: Active-Passive

Single write region. Read replicas in additional regions for dashboard and
audit queries. Failover is manual or semi-automatic. This supports up to
~5M decisions/day with careful connection pooling.

### Phase 2: Active-Active Requirements

Required when single-region write throughput is saturated or when latency
from distant regions exceeds p99 targets.

Prerequisites:
- Conflict-free entity ID allocation (UUIDs already satisfy this)
- Handshake ID partitioning by region prefix
- Cross-region consumption deduplication (binding_hash uniqueness must be global)
- Event ordering: Lamport timestamps or hybrid logical clocks on protocol_events
- Policy propagation: two-phase deployment (stage globally, activate atomically)

Active-active is NOT needed for the 10M/day target if the write region is
properly scaled. It becomes necessary at ~50M/day or for regulatory data
residency requirements.

---

## 6. Latency Targets

These targets assume the canonical OLTP store is within the same region as the
application servers, with connection pooling (PgBouncer or equivalent).

| Operation | p50 | p95 | p99 | Notes |
|---|---|---|---|---|
| Handshake create | < 60ms | < 120ms | < 250ms | 3-table transaction + idempotency check |
| Handshake verify | < 80ms | < 150ms | < 300ms | Binding hash comparison + party lookup |
| Handshake consume | < 40ms | < 80ms | < 150ms | Single-row insert with uniqueness check |
| Commit issue | < 50ms | < 100ms | < 200ms | Insert + nonce uniqueness |
| Receipt submit | < 100ms | < 200ms | < 400ms | Insert + async score trigger |
| Trust profile read | < 30ms | < 60ms | < 120ms | From projection / materialized view |

If async event recording is moved out of the request path (Section 4), the
create and consume operations improve by ~20ms at p50.

---

## 7. Scale Risks

### 7A. Duplicate Storms

**Risk**: Retry-happy clients submit the same handshake creation thousands of
times during a transient failure.

**Mitigation**: Idempotency key with unique index (`uq_handshakes_idempotency_key`).
The first insert wins; subsequent attempts return the existing handshake. Rate
limiting at the ingress layer caps per-entity request volume.

### 7B. Double Consume

**Risk**: Two concurrent requests attempt to consume the same handshake binding.

**Mitigation**: `UNIQUE` constraint on `handshake_consumptions(handshake_id)`
guarantees exactly-once consumption at the database level. Application code uses
`INSERT ... ON CONFLICT DO NOTHING` and checks the affected row count. The partial
indexes `idx_bindings_consumed` and `idx_bindings_unconsumed` make the "is consumed?"
check fast without scanning the full table.

### 7C. Race Conditions in Handshake Lifecycle

**Risk**: A verification and an expiration arrive simultaneously for the same
handshake, producing an invalid state transition.

**Mitigation**: State transitions use `UPDATE ... WHERE status = <expected_status>`
with a check on affected rows. If zero rows are affected, the transition is rejected.
The handshake_events table provides an audit trail for diagnosing contested
transitions.

### 7D. Delegation Blow-Up

**Risk**: Deep or wide delegation chains create O(n) verification work, where n
is the chain depth. A malicious actor creates a 1000-level delegation chain.

**Mitigation**: Protocol-level maximum delegation depth (configurable, default 5).
Delegation chain validation is precomputed at delegation creation time and stored
in `handshake_parties.delegation_chain` as a JSONB array. Verification reads the
precomputed chain rather than traversing it.

### 7E. Noisy Neighbors

**Risk**: A single high-volume entity monopolizes database connections and
degrades performance for all other entities.

**Mitigation**: Per-entity connection quotas at the application layer. Database
connection pooling (PgBouncer) with pool_mode=transaction limits per-connection
hold time. The hot-path indexes ensure that high-volume entities do not cause
full table scans that degrade shared resources.

---

## 8. 10M+/day Architecture Pattern

```
                        ┌─────────────┐
                        │   Ingress   │
                        │  (API GW)   │
                        └──────┬──────┘
                               │
                    ┌──────────┼──────────┐
                    │          │          │
               ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
               │Handshke│ │ Commit │ │Receipt │
               │Service │ │Service │ │Service │
               └────┬───┘ └───┬────┘ └───┬────┘
                    │         │          │
                    └────┬────┘          │
                         │               │
                  ┌──────▼──────┐        │
                  │  Canonical  │◄───────┘
                  │  OLTP Store │
                  │ (PostgreSQL)│
                  └──────┬──────┘
                         │
                    ┌────▼─────┐
                    │  Queue   │
                    │(pg_notify│
                    │ or SQS)  │
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
         │ Event  │ │ Score  │ │ Anchor │
         │Recorder│ │Computer│ │ Worker │
         └────┬───┘ └───┬────┘ └────────┘
              │         │
         ┌────▼─────────▼────┐
         │    Projection     │
         │   (Read Replica   │
         │  / Materialized)  │
         └────────┬──────────┘
                  │
           ┌──────▼──────┐
           │  Dashboard  │
           │  & Audit    │
           │   Queries   │
           └─────────────┘
```

### Flow

1. **Ingress**: API gateway handles authentication, rate limiting, and routing.
   Per-entity rate limits prevent noisy-neighbor effects.

2. **Decision Services**: Stateless services handle handshake, commit, and receipt
   operations. Each service owns its critical-path transaction and returns
   immediately after the OLTP write commits.

3. **Canonical Store**: PostgreSQL with hot-path indexes (migration 048). All
   writes are serializable within their aggregate boundary. Connection pooling
   maintains ~200 active connections across all services.

4. **Queue**: Lightweight async dispatch. Protocol events, score updates, and
   projection refreshes are enqueued after the synchronous transaction commits.
   At-least-once delivery; consumers are idempotent.

5. **Projection Pipeline**: Consumes events and builds read-optimized views.
   Trust profiles, activity summaries, and audit timelines are projected
   continuously. Lag target: < 5 seconds.

6. **Operations**: Dashboard queries, compliance audits, and monitoring all
   read from the projection layer, never from the canonical OLTP store.

### Capacity Estimate

At 10M decisions/day:
- ~115 decisions/second sustained, ~350/second peak (3x burst)
- ~3 OLTP writes per decision (handshake + parties + binding) = ~1,050 writes/second peak
- ~2 async writes per decision (events + score) = ~700 async writes/second peak
- PostgreSQL on a single well-tuned instance handles 5,000+ simple writes/second
- Headroom: ~3x before requiring read replicas, ~5x before requiring sharding

---

## 9. Migration Path

| Milestone | Decisions/day | Architecture |
|---|---|---|
| Current | < 100K | Monolith, single PG, sync events |
| Phase 1 | 100K - 1M | Hot-path indexes, async events, connection pooling |
| Phase 2 | 1M - 10M | Service split, read replicas, projection pipeline |
| Phase 3 | 10M - 50M | Active-passive multi-region, queue infrastructure |
| Phase 4 | 50M+ | Active-active, partitioned writes, global consumption dedup |

Each phase is additive. No migration requires breaking changes to the core schema
or weakening any protocol invariant.
