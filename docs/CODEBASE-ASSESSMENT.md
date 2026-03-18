# EMILIA Protocol — Codebase Assessment
*Generated 2026-03-18 · EP/1.1-v2 · 526 tests passing*

---

## Grade: A− (protocol-excellent, three implementation gaps remain)

The architecture is genuinely differentiated — not "blockchain reviews" but a multi-layer trust
protocol with behavioral-first scoring, policy-as-code evaluation, Sybil resistance that caps
unestablished volume rather than merely discounting it, and cryptographic receipt chaining with
L2 anchoring. The canonical pattern (one evaluator, one writer, no drift) is correctly enforced
across every trust-consuming surface. The gap between a A− and an A is three concrete bugs below.

---

## What is excellent (evidence-anchored)

### 1. Canonical Pattern — zero drift
Every trust read goes through `canonicalEvaluate()` (`lib/canonical-evaluator.js:239`).
Every trust write goes through `lib/canonical-writer.js`. No route contains its own trust logic.
This is rare and means the trust surface is fully auditable at two files.

### 2. Behavioral-first scoring (`lib/scoring-v2.js:48–64`)
```
behavioral 40% · consistency 25% · delivery 12% · product 10% · price 8% · returns 5%
```
Behavioral signals (completion/retry/abandon/dispute) are harder to fake and more predictive
of future routing outcomes than self-reported numeric scores. Putting them at 40% is correct.

### 3. Quality-gated Sybil resistance (`lib/scoring-v2.js:224–230`)
```js
qualityGatedEvidence = establishedEvidence + min(unestablishedEvidence, 2.0)
```
Volume attacks from rotating fake identities mathematically cannot advance confidence past
`provisional` because unestablished submitters contribute at most 2.0 effective evidence total.
This is a genuine protocol innovation.

### 4. Four-factor receipt weighting (`lib/scoring-v2.js:164–172`)
`w = submitter_weight × time_weight × graph_weight × provenance_weight`  
Each factor is independently principled: submitter credibility, recency decay (90-day half-life),
fraud graph penalty, and evidence provenance tier (self_attested 0.3× → oracle_verified 1.0×).

### 5. Ed25519 signature verification (`lib/signatures.js`)
`identified_signed` tier requires a real cryptographic signature over the canonical receipt hash.
Absent or invalid signatures silently downgrade to `self_attested` (0.3×) with a warning rather
than crashing or accepting fraudulent claims. DER construction is correct (OID `1.3.101.112`).

### 6. TOCTOU-safe deduplication (`lib/create-receipt.js:36–109`)
Two-layer defense: Redis `SET NX EX 10` (cross-instance) wraps the check+insert; DB unique
constraint violation (`23505`) is caught as a dedup hit instead of a 500. The in-memory fallback
uses a promise-chain mutex, which is correct for async concurrency (not just a boolean flag).

### 7. Fail-closed rate limiting (`lib/rate-limit.js:89–92`)
Redis errors on sensitive write categories (`submit`, `dispute_write`, `register`, `anchor`)
return 503 + `rate_limit_unavailable` instead of passing requests through. Infrastructure
failure cannot be exploited to bypass write throttling.

### 8. Statistical anomaly detection (`lib/scoring-v2.js:319–388`)
Simplified Welch t-statistic gates alerts on `significance >= 2.0` (roughly 2σ) AND `|delta| >= 10`.
`severe` additionally requires `minN >= 10` in both windows. This eliminates false positives
from high-variance entities with thin sample windows — a common failure mode in naive velocity
tracking systems.

### 9. Retroactive graph weight with audit trail (`lib/sybil.js:199–255`)
When fraud is detected, historical receipts between the pair are retroactively penalized via
chunked updates (50 IDs/batch). Each run inserts a `fraud_flags` audit record regardless of
success. Partial failures are tracked: `{ updated, failed }`. The invariant is enforced:
weight can only decrease retroactively, never increase.

### 10. EP-IX identity continuity (`lib/canonical-evaluator.js:336–406`)
Whitewashing risk is computed from rejected continuity claims. Inherited dispute burden is
summed across predecessor entities. Structured degradation when tables don't exist yet:
`{ _unavailable: true, reason: 'ep_ix_tables_not_deployed' }` — callers can distinguish
"unavailable" from "no continuity" semantically.

---

## Open Issues

### P0 — Dispute response deadline is never written

**File:** `lib/canonical-writer.js:406–421`  
**Symptom:** Every call to `canonicalRespondDispute()` returns 410 "Response deadline has passed."

`canonicalFileDispute` inserts the dispute row (lines 406–421) without setting `response_deadline`.
The check in `canonicalRespondDispute` (line 473) does:
```js
if (new Date(dispute.response_deadline) < new Date())
```
`dispute.response_deadline` is `null`. `new Date(null)` evaluates to `new Date(0)` = January 1,
1970 UTC. The condition is always `true`. Every response attempt is rejected.

**Fix:** In the `canonicalFileDispute` insert (line 406), add:
```js
response_deadline: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
```
This must also be added to the `select('*')` return, and the corresponding DB column must exist.
If the DB has a trigger setting this default, the application code guard is redundant but
harmless — verify against the schema migration.

---

### P0 — `eventLog` is a module-level memory leak

**File:** `lib/canonical-writer.js:50`
```js
const eventLog = [];
```
This array accumulates every write event across every request in the module's lifetime. In a
long-running serverless warm instance, it grows without bound. It is never read or flushed by
anything in the codebase. Since `persistEvent()` now durably writes to `protocol_events`, the
in-memory array adds no value and will eventually cause OOM in warm instances.

**Fix:** Remove `const eventLog = []` and remove the `eventLog.push(event)` line in `emitEvent()`
(line 79). The durable `persistEvent()` call on line 81 already provides everything the
in-memory log was meant to offer.

---

### P1 — `/api/needs/[id]/rate` bypasses trust materialization

**File:** `app/api/needs/[id]/rate/route.js:62`
```js
const result = await createReceipt({ ... });
```
This calls `createReceipt()` directly instead of `canonicalSubmitReceipt()`. The canonical
writer's `canonicalSubmitReceipt()` calls `materializeTrustProfile()` after every new receipt
(canonical-writer.js:127–129). By bypassing it, the entity's `trust_snapshot` and
`trust_materialized_at` are not updated after need ratings. Any trust evaluation within the next
5-minute snapshot TTL will return stale data — the new receipt's contribution is invisible until
the snapshot expires naturally.

**Fix:** Replace the direct `createReceipt()` call with `canonicalSubmitReceipt()`, or explicitly
call `materializeTrustProfile(result.receipt.entity_id)` after a successful return.

---

### P1 — Wrong event type emitted when appeal is filed and resolved

**File:** `lib/canonical-writer.js:614` and `lib/canonical-writer.js:719`

`canonicalAppealDispute` (line 614) emits `WRITE_EVENTS.DISPUTE_RESOLVED` with
`resolution: 'appealed'` when an appeal is *filed* — not resolved. This is semantically wrong
and pollutes the audit trail: downstream consumers filtering for `dispute.resolved` events will
pick up appeal filings.

`canonicalResolveAppeal` (line 719) also emits `WRITE_EVENTS.DISPUTE_RESOLVED` instead of a
distinct appeal-resolution event.

**Fix:** Add two new event types to `WRITE_EVENTS`:
```js
DISPUTE_APPEALED: 'dispute.appealed',
DISPUTE_APPEAL_RESOLVED: 'dispute.appeal.resolved',
```
Use `DISPUTE_APPEALED` in `canonicalAppealDispute` and `DISPUTE_APPEAL_RESOLVED` in
`canonicalResolveAppeal`.

---

### P1 — `.env.example` missing Upstash Redis variables

**File:** `.env.example`

`UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` are referenced in:
- `lib/rate-limit.js:36–37` (rate limiting)  
- `lib/create-receipt.js:18–19` (dedup lock, per-entity quota)

Neither variable appears in `.env.example`. A developer who follows `.env.example` to set up
their environment will silently run with in-memory rate limiting, no cross-instance dedup lock,
and DB-count-only quota checks — without knowing any of this.

**Fix:** Add to `.env.example`:
```
# Upstash Redis (highly recommended — enables distributed rate limiting, dedup locks, and quota tracking)
# Create free tier at https://upstash.com
UPSTASH_REDIS_REST_URL=https://your-redis.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-token
```

---

### P2 — `/api/needs/[id]/rate` has-signal guard uses `!isNaN()` not `Number.isFinite()`

**File:** `app/api/needs/[id]/rate/route.js:54`
```js
const hasSignal = [...].some(v => v != null && !isNaN(v));
```
`!isNaN(Infinity)` is `true`, so `delivery_accuracy: Infinity` passes this guard as "has a
signal." Inside `createReceipt`, `Number.isFinite()` filters it out (scoring-v2.js:180), so
the signal is silently discarded. If Infinity was the only signal provided, `createReceipt`
returns 400 "Receipt produced no meaningful signals" — a confusing error from the wrong layer.

**Fix:** `!isNaN(v)` → `Number.isFinite(v)` on line 54.

---

### P2 — Anchor batch stores full Merkle tree layers (scaling concern)

**File:** `lib/blockchain.js:289`
```js
tree_layers: tree.layers,
```
For a 1,000-receipt batch, `tree.layers` contains ~2,000 hashes × 64 bytes = ~128 KB stored as
JSON per batch. At scale this bloats `anchor_batches` rapidly. Individual proofs are already
stored per receipt (`merkle_proof` field, line 307). The full layers are only useful for
re-deriving proofs — which can be done from receipt hashes on demand.

**Fix:** Store `tree_layers: null` (or omit) and add a `leaves: leafHashes` field instead.
Proofs can be re-generated from leaves. Or keep layers but add a retention policy.

---

### P2 — Anchor batch proof update is a serial N-query loop

**File:** `lib/blockchain.js:302–311`
```js
for (const p of proofs) {
  await supabase.from('receipts').update({ ... }).eq('receipt_id', p.receipt_id);
}
```
For 1,000 receipts this issues 1,000 sequential round-trips inside the anchor cron. At 10ms
per round-trip that's 10 seconds of DB load at the end of every anchor cycle.

**Fix:** Use a single `upsert` or a Supabase RPC that accepts the batch as JSON and does a
single `UPDATE ... FROM jsonb_to_recordset(...)` operation.

---

### P2 — `/api/needs/broadcast` rate limited as `submit`

**File:** `middleware.js:19`
```js
if (pathname.startsWith('/api/needs/broadcast')) return 'submit';
```
Broadcasts share the receipt submission quota (30/min per key). A high-broadcast agent gets
throttled on receipt submission and vice versa. These workloads have different traffic shapes.

**Fix:** Add `broadcast: { window: 60, max: 10 }` to `RATE_LIMITS` and return `'broadcast'`
for the broadcast path.

---

## Test coverage gaps (526 tests passing — these paths are untested)

| Path | Missing test |
|------|-------------|
| `canonicalRespondDispute` with null `response_deadline` | Should verify 410 vs the bug |
| `canonicalAppealDispute` event type | Assert event is `dispute.appealed`, not `dispute.resolved` |
| `/api/needs/[id]/rate` with `Infinity` signal | Should not produce confusing 400 from wrong layer |
| `runAnchorBatch` with 1,001 receipts | Layer size regression test |
| `materializeTrustProfile` not called after need rating | Integration test for stale snapshot |

---

## Architecture checklist

| Property | Status |
|----------|--------|
| Single evaluator, no drift | ✅ `canonicalEvaluate()` called by all 10 surfaces |
| Single writer, no drift | ✅ All writes through `canonical-writer.js` |
| Sybil volume cap (quality gate) | ✅ `establishedEvidence + min(unestablished, 2.0)` |
| Behavioral-first weighting | ✅ 40% behavioral, 25% consistency |
| TOCTOU-safe dedup | ✅ Redis SET NX + DB constraint fallback |
| Fail-closed rate limiting | ✅ Upstash fail-closed for all write categories |
| Ed25519 provenance verification | ✅ `lib/signatures.js` wired into receipt path |
| Retroactive weight with audit | ✅ Chunked, partial-failure tracked |
| Statistical anomaly detection | ✅ Welch t-statistic, min N=5 per window |
| Per-entity daily quota | ✅ Redis INCR atomic, DB fallback |
| Event durability | ✅ `protocol_events` table via fire-and-forget |
| Dispute response deadline bug | ❌ `response_deadline` never written |
| eventLog memory leak | ❌ Module-level array, never cleared |
| Trust snapshot after need rating | ❌ `materializeTrustProfile` skipped |
| Appeal event types | ❌ Wrong `WRITE_EVENTS` constant |
| `.env.example` completeness | ❌ Missing Upstash vars |

