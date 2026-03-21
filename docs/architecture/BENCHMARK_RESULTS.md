# EP Benchmark Results

**Version:** 1.0
**Purpose:** Prove the EP protocol kernel is lightweight. Every number here is auditable against `tests/benchmark.test.js`.

---

## 1. What We Measure

**Code-path overhead** — the CPU time consumed by EP protocol logic (validation, hashing, state transitions, policy evaluation) with all database I/O mocked out.

This is intentionally NOT an end-to-end benchmark. DB latency is infrastructure-dependent (co-located Postgres: ~5ms/round-trip; edge function to managed DB: ~20-50ms). By isolating the protocol kernel, we prove that EP itself adds minimal overhead on top of whatever infrastructure it runs on.

---

## 2. Why

EP's value proposition includes being lightweight enough for real-time agent-to-agent trust decisions. If the protocol logic itself were expensive, no amount of infrastructure optimization could fix it. These benchmarks prove:

1. The handshake ceremony is dominated by I/O, not computation
2. SHA-256 binding hashes are sub-millisecond
3. Policy evaluation (trust profile + gate check) is pure computation under 5ms
4. The consume path is trivially cheap (zero hash computations by design)

---

## 3. SLO Targets

From GOD FILE Section 13.1 — code-path overhead SLOs (mock-based, not end-to-end):

| Operation | p50 | p95 | p99 |
|---|---|---|---|
| Handshake Create | < 60ms | < 150ms | < 300ms |
| Handshake Verify | < 80ms | < 200ms | < 400ms |
| Consume | < 40ms | < 120ms | < 250ms |
| Binding Hash (SHA-256) | < 1ms | < 1ms | < 2ms |
| Policy Evaluation | < 2ms | < 3ms | < 5ms |

These SLOs account for mock infrastructure overhead (Vitest mock dispatch, in-memory table simulation). Real production overhead will be lower for the pure computation paths and higher for the I/O paths.

---

## 4. How to Run

```bash
npx vitest run tests/benchmark.test.js
```

Results are printed to stdout with the `[BENCH]` prefix. Each line reports p50, p95, p99, mean, min, and max latencies.

---

## 5. Methodology

- **Iterations:** 1,000 per operation
- **Percentile calculation:** Sort all timings, compute p50/p95/p99 by index
- **Timer:** `performance.now()` (sub-millisecond precision)
- **Isolation:** Each iteration creates a fresh table simulator to prevent accumulation effects
- **Warm-up:** None (first-iteration cold-start is intentionally included in percentiles)
- **Assertions:** Tests fail if any percentile exceeds SLO bounds

---

## 6. What's Included vs. Excluded

| Component | Included | Rationale |
|---|---|---|
| Input validation | Yes | Part of every request |
| SHA-256 hash computation | Yes | Core protocol operation (5 hashes on create) |
| Canonical JSON serialization | Yes | Required for deterministic hashing |
| Nonce generation (crypto.randomBytes) | Yes | Real crypto, not mocked |
| Policy resolution | Yes (mock) | Logic exercised, I/O mocked |
| Trust profile computation | Yes | Pure computation, no mocking needed |
| Policy gate evaluation | Yes | Pure computation, no mocking needed |
| Supabase client calls | Mocked | In-memory table simulator returns immediately |
| Network I/O | Excluded | Infrastructure-dependent |
| TLS handshakes | Excluded | Infrastructure-dependent |
| Connection pooling | Excluded | Infrastructure-dependent |

---

## 7. Payload Size Analysis

Exact byte sizes of key payloads under normal conditions (from PROTOCOL_WEIGHT.md Section 3):

| Payload | Request Body | Response Body | Total Wire |
|---|---|---|---|
| Handshake Create | ~400 bytes | ~800 bytes | ~1.2 KB |
| Handshake Verify | ~100 bytes | ~400 bytes | ~500 bytes |
| Consume | ~150 bytes | ~300 bytes | ~450 bytes |
| Trust Decision (policy eval response) | N/A | ~400 bytes | ~400 bytes |
| **Full ceremony** (create + 2 presents + verify + consume) | — | — | **~4.0 KB** |

For comparison:
- OAuth2 token exchange: 2-4 KB
- SAML assertion: 5-15 KB
- EP full ceremony: ~4.0 KB (stronger guarantee: multi-party, policy-bound, one-time-use, auditable)

---

## 8. Round-Trip Analysis

DB round-trip counts per operation (from PROTOCOL_WEIGHT.md Section 1):

| Operation | DB Reads | DB Writes | Event Writes | Total Round-Trips |
|---|---|---|---|---|
| Initiate Handshake | 0-2 | 3 | 1 | 4-5 (typical) |
| Present | 2-3 | 1-2 | 1-2 | 4-5 (typical) |
| Verify | 4 | 3+N | 1 | 8+N (N = party count, typically 2) |
| Consume | 1 | 2 | 0 | 3 |
| **Full ceremony** | **7-10** | **9+N** | **3-4** | **19-23** |

### Key observations:

1. **Verify is the heaviest** operation (8-10 round-trips) because it is the decision point. The N party status updates are sequential but could be batched.
2. **Consume is the lightest** (3 round-trips). Its integrity guarantee comes from a DB unique constraint, not application logic. Zero hash computations.
3. **Hash computations** are concentrated in Initiate (5 SHA-256 hashes) and are sub-millisecond each.
4. **No operation makes external HTTP calls.** All trust state is local to the database.

---

## 9. Invariants (from PROTOCOL_WEIGHT.md Section 5)

These properties must hold for EP to claim lightweightness. Violations are bugs.

1. No trust-path operation performs more than 10 DB round-trips (except Verify, which scales with party count).
2. No trust-path operation computes more than 6 hashes.
3. No trust-path operation makes external HTTP calls. All trust state is local.
4. Consume performs zero hash computations. Integrity is enforced by the database, not application code.
5. Event persistence never blocks trust-bearing writes (except handshake events, which are mandatory for audit immutability).
6. A full trust ceremony transfers less than 5 KB on the wire.
7. A full trust ceremony completes in under 500ms on a co-located database.
