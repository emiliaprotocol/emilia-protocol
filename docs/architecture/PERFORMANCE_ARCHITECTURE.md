# EP Performance Architecture

**Date:** 2026-03-28
**Status:** Production (Vercel Pro + Supabase us-west-2)

---

## Hot-Path Architecture

Every protocol write goes through this pipeline:

```
Request → Middleware → Auth → Protocol Write → RPC → Response
```

### 1. Middleware (Edge)

Protocol write routes (`POST /api/handshake`, `/verify`, `/present`, `/revoke`) **bypass** the Upstash rate limiter entirely. Auth + DB-level idempotency provide sufficient protection without the network roundtrip penalty.

Non-protocol routes still go through Upstash-backed rate limiting.

### 2. Auth: `resolve_authenticated_actor()` RPC

Single Postgres function replaces 3 serial REST API calls:

| Before | After |
|--------|-------|
| `api_keys` lookup (REST) | Single RPC call |
| `last_used_at` update (REST) | Inside same transaction |
| `entities` lookup (REST) | Inside same transaction |

**Security invariants preserved:**
- Identity comes from auth, never from request body
- Revoked keys fail immediately (no cache)
- Inactive entities fail immediately
- Malformed records fail closed (500, not 200)

### 3. Handshake Create: `create_handshake_atomic()` RPC

Single Postgres function replaces 4+ serial REST API calls:

| Operation | Before | After |
|-----------|--------|-------|
| Handshake insert | REST call 1 | Inside RPC |
| Party records insert | REST call 2 | Inside RPC |
| Binding insert | REST call 3 | Inside RPC |
| Handshake event | REST call 4 | Inside RPC |
| Protocol event | REST call 5 | Inside RPC |

All writes happen in a single Postgres transaction. No partial state survives.

### 4. Handshake Verify: `verify_handshake_writes()` RPC

Reads happen in JS (parties, presentations, binding, policy). Verification logic runs in JS. Then all writes are batched:

| Operation | Before | After |
|-----------|--------|-------|
| Result insert | REST call 1 | Inside RPC |
| Event insert | REST call 2 | Inside RPC |
| Status update | REST call 3 | Inside RPC |
| Party updates (N) | REST calls 4-N | Inside RPC |
| Binding consume | REST call N+1 | Inside RPC |
| Protocol event | REST call N+2 | Inside RPC |

### 5. Signoff Consume: `consume_signoff_atomic()` RPC

| Operation | Before | After |
|-----------|--------|-------|
| Event insert | REST call 1 | Inside RPC |
| Consumption insert | REST call 2 | Inside RPC |
| Attestation update | REST call 3 | Inside RPC |
| Protocol event | REST call 4 | Inside RPC |

Unique constraint on `signoff_id` in `signoff_consumptions` enforces one-time consumption at the DB level.

### 6. Overload Guard

Per-instance concurrency counter (`MAX_CONCURRENT=50`). When exceeded:
- Returns `503 Service Unavailable`
- Includes `Retry-After: 2` header
- No request queueing, no timeout collapse
- Prefers bounded rejection over unbounded wait

---

## Roundtrip Budget

| Endpoint | Roundtrips (before) | Roundtrips (after) | Floor |
|----------|--------------------|--------------------|-------|
| Create | 7 serial | 2 (auth RPC + create RPC) | ~65ms |
| Verify | 6+ serial | 3 (auth + reads + write RPC) | ~120ms |
| Consume | 4 serial | 2 (auth RPC + consume RPC) | ~80ms |

---

## Deployment Configuration

```json
{
  "functions": {
    "app/api/**/*.js": {
      "maxDuration": 60,
      "memory": 1024
    }
  },
  "regions": ["pdx1"]
}
```

- **Region:** `pdx1` (Portland) — co-located with Supabase `us-west-2`
- **Fluid Compute:** Default on all plans (warm instance reuse)
- **Connection pooling:** Supabase pooler with dedicated IPv4
