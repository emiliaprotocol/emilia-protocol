# EP Operating Envelope

**Date:** 2026-03-28
**Environment:** Vercel Pro (pdx1) + Supabase (us-west-2) + Upstash Redis

---

## Supported Band (up to ~50 concurrent users)

The system operates within design parameters at this concurrency level.

### Endpoint Performance

| Endpoint | p50 | min | p90 |
|----------|-----|-----|-----|
| Handshake create | 253ms | 211ms | 336ms |
| Present (per party) | 355ms | 302ms | 444ms |
| Verify (accepted) | 351ms | 294ms | 471ms |
| Challenge | 274ms | 230ms | 352ms |
| Attest | 274ms | 232ms | 346ms |
| Consume | 201ms | 167ms | 253ms |

### Scenario Performance

| Scenario | p50 | min | p90 |
|----------|-----|-----|-----|
| Full 7-step signoff flow | 2,108ms | 1,837ms | 10,372ms |
| Handshake create (isolated) | 236ms | 187ms | 364ms |

### Correctness Guarantees (Supported Band)

| Guarantee | Status |
|-----------|--------|
| Zero error rate | Proven (0.0% at 50 VUs) |
| All 7 steps complete | Proven (6,524 checks, 0 failed) |
| Atomic transactions | Enforced (single RPC per write path) |
| Idempotency | DB-enforced unique constraints |
| Event completeness | Mandatory event-first ordering |
| One-time consumption | Unique constraint + consumed_at guard |

---

## Overload Band (50-500 concurrent users)

The system degrades safely with explicit backpressure.

### Behavior

| Behavior | Expected |
|----------|----------|
| Admission control | HTTP 503 + Retry-After: 2 |
| Response time | < 5ms for 503 rejection |
| Partial writes | None |
| Event loss | None |
| Duplicate consumption | None |
| Recovery | Immediate on load reduction |

### Staircase Results (10 to 500 VUs)

| Metric | Value |
|--------|-------|
| min | 70ms |
| p50 | 468ms |
| Success rate | 86.6% |
| Total requests | 6,727 |

Above the supported band, the system prefers **bounded rejection over unbounded queueing**. No correctness violations occur under overload.

---

## What "Supported" Means

A concurrency level is "supported" only if:

1. Success rate is high (> 95%)
2. Correctness assertions pass (zero violations)
3. Latency is within declared targets
4. 503s are not dominating the response mix

If 503s exceed ~20% of responses, that concurrency level is in the **overload band**, not the supported band.

---

## Endpoint-Specific Notes

### Create (fastest)
- Single RPC: `create_handshake_atomic()`
- Auth RPC: `resolve_authenticated_actor()`
- Total: 2 DB roundtrips
- Floor: ~187ms

### Present (slowest per-step)
- Goes through `protocolWrite()` wrapper
- Each party presents separately with own API key
- Two presents per mutual handshake
- Optimization target for next phase

### Verify (moderate)
- Reads: parties, presentations, binding, policy (parallelized)
- Writes: single RPC `verify_handshake_writes()`
- Total: 2 roundtrips (read bundle + write RPC)

### Challenge / Attest (moderate)
- Validation + event + record insert
- Not yet RPC-optimized

### Consume (fast)
- Single RPC: `consume_signoff_atomic()`
- One-time consumption enforced at DB level
- Floor: ~167ms
