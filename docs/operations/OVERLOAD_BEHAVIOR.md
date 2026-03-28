# EP Overload Behavior

**Status:** Production
**Date:** 2026-03-28

---

## Design Principle

EP prefers **bounded rejection** over **unbounded queueing**.

Under overload, the system returns fast 503 responses with explicit retry semantics. It does not queue requests into timeout collapse.

---

## Overload Response

When concurrency exceeds the per-instance limit:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 2
Content-Type: application/json

{
  "error": "Service overloaded",
  "retry_after": 2
}
```

### Fields

| Field | Value | Meaning |
|-------|-------|---------|
| HTTP status | 503 | Service temporarily unavailable |
| `Retry-After` | 2 | Retry after 2 seconds |
| `error` | `Service overloaded` | Machine-readable reason |

---

## What Happens Under Overload

| Guarantee | Status |
|-----------|--------|
| Fast rejection (< 5ms) | Yes |
| Explicit retry semantics | Yes |
| No partial writes | Yes |
| No silent event omission | Yes |
| No ambiguous timeout | Yes |
| No duplicate consumption | Yes |
| No stale binding reuse | Yes |
| Immediate recovery on load reduction | Yes |

## What Never Happens Under Overload

- Requests do NOT queue indefinitely waiting for a function slot
- Handshakes are NOT partially created (no parties without binding, no binding without event)
- Events are NOT silently dropped
- Signoffs are NOT double-consumed
- Auth is NOT weakened or bypassed
- Rate limiting is NOT the bottleneck (protocol routes bypass Upstash)

---

## Operating Bands

### Supported Band (up to ~100 concurrent users)

| Metric | Target |
|--------|--------|
| p50 | < 250ms |
| p90 | < 500ms |
| Error rate | < 1% |
| Throughput | ~40 req/s |
| Correctness | All invariants hold |

### Overload Band (100-500 concurrent users)

| Behavior | Expected |
|----------|----------|
| Admission control | 503 + Retry-After |
| Partial writes | None |
| Event loss | None |
| Correctness | All invariants hold |
| Recovery time | Immediate |

---

## Implementation

Per-instance concurrency counter in the route handler:

```javascript
let _inflight = 0;
const MAX_CONCURRENT = 50;

if (_inflight >= MAX_CONCURRENT) {
  return Response.json(
    { error: 'Service overloaded', retry_after: 2 },
    { status: 503, headers: { 'Retry-After': '2' } }
  );
}
_inflight++;
try { /* handle request */ }
finally { _inflight--; }
```

Each Vercel serverless function instance tracks its own concurrency. Under Fluid Compute, warm instances share load across invocations.

---

## Client Guidance

When receiving a 503:

1. Wait the `Retry-After` duration (2 seconds)
2. Retry with the same idempotency key
3. The system will either accept the request or return another 503
4. Idempotency keys ensure no duplicate creates on retry

Do NOT:
- Retry immediately without waiting
- Retry without the original idempotency key
- Interpret 503 as a permanent failure
