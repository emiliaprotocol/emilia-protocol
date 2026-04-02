# Health Probes — Kubernetes & Container Orchestration

## Overview

EMILIA Protocol exposes a single health endpoint at `GET /api/health` that supports
both liveness and readiness probe patterns. The endpoint performs live database checks
and returns structured JSON — do not cache this response.

---

## Endpoint

```
GET /api/health
```

**Authentication:** None required.
**Cache:** `no-store` (enforced by `Cache-Control: no-store, no-cache` response header).

### Response shape (200 OK — healthy)

```json
{
  "status": "ok",
  "timestamp": "2026-04-02T14:00:00.000Z",
  "db_latency_ms": 4,
  "checks": {
    "database": "ok",
    "write_guard": "ok",
    "signoff_queue_depth": 3,
    "schema_version": "20260401_001"
  }
}
```

### Response shape (503 Service Unavailable — degraded)

```json
{
  "status": "degraded",
  "timestamp": "2026-04-02T14:00:00.000Z",
  "error": "Database unreachable"
}
```

---

## Kubernetes Configuration

### Liveness Probe

The liveness probe determines whether the container should be restarted. Use a lenient
failure threshold to avoid restart loops during database maintenance windows.

```yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: 3000
    scheme: HTTP
  initialDelaySeconds: 15      # Allow Next.js startup + DB connection pool warmup
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3          # Restart after 3 consecutive failures (~90s)
  successThreshold: 1
```

### Readiness Probe

The readiness probe determines whether the pod should receive traffic. Use a tighter
failure threshold so degraded pods are quickly removed from the load balancer rotation.

```yaml
readinessProbe:
  httpGet:
    path: /api/health
    port: 3000
    scheme: HTTP
  initialDelaySeconds: 10      # EP is ready faster than liveness threshold
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 2          # Remove from rotation after 2 failures (~20s)
  successThreshold: 2          # Require 2 successes before re-adding to rotation
```

### Startup Probe

For slow-start environments (e.g., cold container with large dependencies):

```yaml
startupProbe:
  httpGet:
    path: /api/health
    port: 3000
  failureThreshold: 30         # Allow up to 5 minutes (30 × 10s) for startup
  periodSeconds: 10
  timeoutSeconds: 3
```

---

## Docker Compose / Standalone

```yaml
# docker-compose.yml
services:
  emilia-protocol:
    image: emilia-protocol:latest
    ports:
      - "3000:3000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
```

---

## Interpreting Health Check Fields

| Field | Meaning | Action if degraded |
|---|---|---|
| `status` | `"ok"` or `"degraded"` | Alert if `degraded` for >2 minutes |
| `db_latency_ms` | Round-trip time for a Supabase ping | Alert if >500ms consistently |
| `checks.database` | DB connectivity and basic query | Pod restart if `"error"` |
| `checks.write_guard` | Write-guard proxy functional | Alert + investigate if not `"ok"` |
| `checks.signoff_queue_depth` | Pending signoff challenges | Alert ops team if >100 |
| `checks.schema_version` | Latest applied migration ID | Alert if stale after deploy |

---

## Graceful Shutdown

EP handles SIGTERM gracefully via `lib/shutdown.js`:

1. Stops accepting new writes immediately.
2. Drains in-flight `protocolWrite()` calls (10-second timeout).
3. Closes the Supabase connection pool.
4. Exits with code 0.

Kubernetes `terminationGracePeriodSeconds` should be set to at least **30 seconds** to
allow drain completion plus pool shutdown:

```yaml
spec:
  terminationGracePeriodSeconds: 30
```

The `preStop` hook is not needed — EP's instrumentation.js registers SIGTERM handlers
directly via Next.js `register()`.

---

## SLOs for Health Endpoint

| Metric | Target |
|---|---|
| Health endpoint p99 latency | < 200ms |
| Health endpoint availability | > 99.9% |
| False positive degraded status | < 1 per day |

The health endpoint performs a live DB read on every call. At high probe frequency
(< 5s intervals), consider that each probe consumes a DB connection. The default
30s liveness / 10s readiness interval is appropriate for production deployments.
