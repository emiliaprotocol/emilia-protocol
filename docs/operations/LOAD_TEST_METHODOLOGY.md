# EP Load Test Methodology

**Tool:** k6 (Grafana)
**Target:** Production (www.emiliaprotocol.ai)
**Auth:** Dual API keys (initiator + responder entities)

---

## Fixture Strategy

### Pre-created fixtures
- Minimal load-test policy (`load_test_minimal_v1`) — no required claims or hashes
- Initiator entity (`k6-loadtest`) with API key
- Responder entity (`k6-responder`) with API key
- Policy ID: `d1f14bbc-b4df-4ba3-94ef-998d236c0dc0`

### Runtime fixtures
- Each VU iteration creates a fresh handshake (tests the full create path)
- Idempotency keys prevent duplicate creates on retry
- Binding hashes are captured from create response and forwarded to verify/challenge

---

## Test Profiles

### Supported-Band Test (standardStages)
```
warmup:    30s →  5 VUs
sustained: 2m  → 50 VUs
cooldown:  30s →  0 VUs
```

### Staircase Test
```
step 1: 60s → 10 VUs
step 2: 60s → 25 VUs
step 3: 60s → 50 VUs
step 4: 60s → 100 VUs
step 5: 60s → 250 VUs
step 6: 60s → 500 VUs
cooldown: 30s → 0 VUs
```

### Concurrent Abuse Test
```
100 VUs × 1 iteration each (shared-iterations)
All racing to consume the same signoff
```

---

## Pass/Fail Criteria

### Supported Band
| Criterion | Threshold |
|-----------|-----------|
| Error rate | < 1% |
| p50 create | < 300ms |
| p95 create | < 1,000ms |
| Full flow completes | All 7 steps |
| Correctness checks | 0 failures |

### Overload Band
| Criterion | Threshold |
|-----------|-----------|
| 503 responses | Expected and acceptable |
| Timeout deaths | Zero (replaced by fast 503) |
| Partial writes | Zero |
| Event omission | Zero |
| Duplicate consumption | Zero |

---

## Test Files

| File | Tests | VU Target |
|------|-------|-----------|
| `handshake-create.js` | Create endpoint at supported band | 50 |
| `handshake-verify.js` | Verify endpoint with pre-created fixtures | 50 |
| `signoff-flow.js` | Full 7-step mutual accepted flow | 50 |
| `consume.js` | Consume endpoint with pre-created signoffs | 50 |
| `concurrent-abuse.js` | Race condition: 100 VUs on 1 signoff | 100 |
| `staircase.js` | Escalating load to find knee | 10-500 |

---

## Running Tests

```bash
export EP_BASE_URL=https://www.emiliaprotocol.ai
export EP_API_KEY=<initiator-key>
export EP_RESPONDER_API_KEY=<responder-key>
export EP_ENTITY_REF=k6-loadtest
export EP_RESPONDER_REF=k6-responder

# Supported band
k6 run load-tests/handshake-create.js
k6 run load-tests/signoff-flow.js

# Staircase
k6 run load-tests/staircase.js

# Concurrent abuse
k6 run load-tests/concurrent-abuse.js
```

---

## What Counts as Overload

A test step is in the **overload band** when:
- 503 responses exceed 20% of the response mix
- p95 exceeds 10x the supported-band p50
- Request rate drops below 50% of peak due to queueing

The system is designed to enter overload gracefully — fast 503 rejection replaces timeout-based failure.
