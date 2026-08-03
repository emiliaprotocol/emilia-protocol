# Application health probes

EMILIA exposes separate liveness and readiness contracts. Neither response is
cached, and neither discloses dependency names, schema versions, counts,
latencies, or secret values.

## Process liveness

`GET /api/live` proves only that the Next.js process can answer HTTP:

```json
{ "status": "live" }
```

It always returns HTTP 200 while the process can serve the route. Database or
Agent Record dependency failure must not turn liveness into a restart loop.

## Application readiness

`GET /api/health` is the traffic-readiness contract. In production it checks
the Agent Record signing and durable rate-limit configuration, Supabase
configuration, the one-way database creation capability match, and all bounded
Agent Record RPC entry points. It also checks the private storage ACL, forced
RLS, source-reader policy, and immutable-trigger contract. Results are briefly coalesced per process, but
the HTTP response itself is `no-store`.

Ready response (HTTP 200):

```json
{ "status": "ready" }
```

Any false, missing, malformed, unavailable, or thrown dependency response
(HTTP 503):

```json
{ "status": "not_ready" }
```

## Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /api/live
    port: 3000
  initialDelaySeconds: 15
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /api/health
    port: 3000
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 2
  successThreshold: 2

startupProbe:
  httpGet:
    path: /api/live
    port: 3000
  failureThreshold: 30
  periodSeconds: 10
  timeoutSeconds: 3
```

For Docker or standalone process supervision, use `/api/live` for restart
decisions and `/api/health` for load-balancer admission. A successful liveness
probe is never evidence that migrations, capability provisioning, or production
dependencies are ready.
