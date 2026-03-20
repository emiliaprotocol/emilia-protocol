# EMILIA Protocol -- Observability

## Telemetry Architecture

Every call to `protocolWrite()` emits a structured JSON log line with `_ep_telemetry: true`. This is fire-and-forget -- telemetry failures never block the write path.

Telemetry payload:
```json
{
  "_ep_telemetry": true,
  "event_id": "uuid",
  "command_type": "submit_receipt",
  "aggregate_type": "receipt",
  "aggregate_id": "uuid",
  "actor": "entity-id-or-anonymous",
  "duration_ms": 145,
  "timestamp": "2026-03-20T12:00:00.000Z"
}
```

Filter application logs by `_ep_telemetry` to isolate protocol write events from general application logging.

## What to Monitor

### 1. protocolWrite Success/Failure Rates by Command Type

**Why**: The protocol write pipeline is the single choke point for all trust-changing operations. Failures here mean trust operations are not completing.

**Metric**: Count of successful vs failed `protocolWrite()` calls, grouped by `command_type`.

**Source**: Telemetry logs (`_ep_telemetry: true` entries indicate success). Failures throw `ProtocolWriteError` and should be captured by your error tracking system.

**Alert threshold**:
- Error rate > 5% on any command type over a 5-minute window: **S3**
- Error rate > 20% or all commands failing: **S1**
- `EVENT_PERSISTENCE_FAILED` errors (step 8 failure): **S1** -- this means events cannot be logged, and all writes are being rejected

### 2. Event Emission Latency

**Why**: The `duration_ms` field in telemetry captures the full pipeline time (validation through event persistence). Latency spikes indicate database issues or contention.

**Metric**: p50, p95, p99 of `duration_ms` from telemetry logs, grouped by `command_type`.

**Baseline expectations**:
| Command type | Expected p95 |
|---|---|
| `submit_receipt`, `submit_auto_receipt` | < 300ms |
| `confirm_receipt` | < 300ms |
| `issue_commit` | < 500ms |
| `verify_commit` | < 500ms |
| `file_dispute`, `resolve_dispute` | < 500ms |
| `initiate_handshake` | < 500ms |
| `verify_handshake` | < 1000ms (includes policy resolution + binding consumption) |

**Alert threshold**:
- p95 > 2x baseline for any command type over 5 minutes: **S3**
- p95 > 5x baseline: **S2**

### 3. Consumption Success/Failure Ratio

**Why**: Handshake binding consumption is the replay-prevention mechanism. A high failure rate could indicate expired bindings, replay attempts, or system clock drift.

**Metric**: Ratio of successful `verify_handshake` commands to failed ones.

**Failure categories to track**:
- `binding_expired`: binding TTL exceeded (normal if clients are slow)
- `binding_already_consumed`: replay attempt or double-processing
- `policy_hash_mismatch`: policy changed between initiation and verification
- `policy_not_found` / `policy_load_failed`: policy resolution failure

**Alert threshold**:
- `binding_already_consumed` > 0 in any 1-hour window: **S2** (potential replay attack or double-processing bug)
- `policy_hash_mismatch` > 5% of verifications: **S2** (policy is changing during active handshakes)
- `policy_not_found` spike: **S2** (see Incident Response for cascade failure procedure)

### 4. Write-Guard Violation Alerts

**Why**: The write guard (`lib/write-guard.js`) throws `WRITE_DISCIPLINE_VIOLATION` when a route handler attempts to directly mutate a trust table. Any occurrence in production means a code defect bypassed the intended architecture.

**Metric**: Count of `WRITE_DISCIPLINE_VIOLATION` errors.

**Alert threshold**:
- Any occurrence: **S1** -- a trust table is being written outside `protocolWrite()`.

**Source**: Error logs containing the string `WRITE_DISCIPLINE_VIOLATION`.

### 5. Policy Resolution Failures

**Why**: Policy resolution is fail-closed. Failures block all handshake operations.

**Metric**: Count of policy resolution errors from `resolvePolicy()`, `loadPolicy()`, `loadPolicyById()`.

**Alert threshold**:
- > 3 failures in 5 minutes: **S2**
- Sustained failures (> 1 minute): **S1** (cascade failure, see Incident Response)

### 6. Handshake Verification Outcomes

**Why**: Handshake verification is the pre-action trust enforcement gate. Tracking outcomes reveals whether the trust system is functioning as intended.

**Metric**: Count of handshake verification results by outcome category.

**Categories**:
- `accepted`: verification succeeded, binding consumed
- `rejected_claims`: presented claims did not satisfy policy requirements
- `rejected_expired`: binding was expired
- `rejected_consumed`: binding was already consumed
- `rejected_policy`: policy hash mismatch or policy not found
- `error`: internal error during verification

### 7. Rate Limiting

**Why**: Rate limiting protects the write path from abuse. Monitoring reveals attack patterns and misconfiguration.

**Metric**: Count of `429` responses, grouped by `rateCategory`.

**Rate limit categories and their limits** (from `lib/rate-limit.js`):

| Category | Window | Max | Fail behavior |
|---|---|---|---|
| `register` | 3600s | 10/hr per IP | Fail-closed |
| `submit` | 60s | 30/min per key | Fail-closed |
| `read` | 60s | 120/min per IP | Fail-open |
| `anchor` | 21600s | 1/6hr | Fail-closed |
| `waitlist` | 3600s | 5/hr per IP | Fail-open |
| `dispute_write` | 3600s | 5/hr per key | Fail-closed |
| `report_write` | 3600s | 3/hr per IP | Fail-open |

**Alert threshold**:
- Rate limiter backend unavailable (503 responses with `rate_limit_unavailable`): **S2**
- Sustained spike in 429s on `submit` or `dispute_write`: **S3** (may indicate attack or legitimate load increase)

### 8. Abuse Detection

**Why**: The procedural justice layer (`lib/procedural-justice.js`) detects abuse patterns.

**Patterns to monitor** (from `ABUSE_PATTERNS`):

| Pattern | Threshold | Action |
|---|---|---|
| `repeated_identical_reports` | 5 identical reports in 24h | `rate_limit` |
| `brigading` | 10 reports against same entity in 24h | `flag_for_review` |
| `ip_report_flooding` | 10 reports from same IP in 24h | `rate_limit` |
| `retaliatory_filing` | Dispute filed against entity that recently filed against filer | `flag_for_review` |
| `continuity_challenge_spam` | 2 challenges against same continuity from same source in 7d | `rate_limit` |
| `dispute_flooding` | 10 disputes from same entity in 24h | `rate_limit` |

**Alert threshold**:
- `brigading` pattern triggered: **S3** (potential coordinated attack on an entity)
- `retaliatory_filing` triggered: **S4** (log for operator review)

### 9. Health Check

**Why**: The `/api/health` endpoint provides a consolidated status view.

**Metric**: Poll `/api/health` periodically (e.g., every 60 seconds).

**Alert threshold**:
- `status: "degraded"`: **S3**
- Health check returns non-200: **S1**
- `checks.database.status` not `"ok"`: **S2**
- `checks.rate_limiter.backend` is `"in_memory"` in production: **S3**

## Key Metrics Summary

| Metric | Source | Alert Level |
|---|---|---|
| protocolWrite error rate by command | Telemetry logs | S1/S3 |
| protocolWrite latency p95 | Telemetry logs | S2/S3 |
| EVENT_PERSISTENCE_FAILED count | Error logs | S1 |
| WRITE_DISCIPLINE_VIOLATION count | Error logs | S1 |
| binding_already_consumed count | Application logs | S2 |
| Policy resolution failure rate | Application logs | S1/S2 |
| HTTP 429 rate by category | Access logs | S2/S3 |
| HTTP 503 rate (rate_limit_unavailable) | Access logs | S2 |
| Health check status | `/api/health` | S1/S3 |
| Abuse pattern triggers | Application logs | S3/S4 |

## Dashboard Recommendations

### Dashboard 1: Protocol Write Pipeline

- Total writes per minute (stacked by command type)
- Error rate per command type (line chart)
- Latency p50/p95/p99 per command type
- Idempotency cache hit rate

### Dashboard 2: Handshake Operations

- Handshake initiations per minute
- Verification success/failure ratio
- Failure breakdown by category (expired, consumed, policy mismatch)
- Binding consumption latency

### Dashboard 3: Security and Abuse

- Rate limit rejections per minute by category
- Write-guard violations (should always be zero)
- Abuse pattern triggers by pattern type
- API key authentication failures by error code (`key_not_found`, `key_revoked`, `entity_inactive`)

### Dashboard 4: Infrastructure

- Health check status (healthy/degraded)
- Database query latency
- Rate limiter backend status
- Blockchain anchoring status and last anchor timestamp
- Cron job execution status (`/api/blockchain/anchor`, `/api/cron/expire`)

## Log Aggregation Setup

### Structured Log Fields

All EP telemetry logs are JSON with `_ep_telemetry: true`. Configure your log aggregation to:

1. Parse JSON log lines
2. Index on: `command_type`, `aggregate_type`, `actor`, `duration_ms`, `event_id`
3. Create a saved search for `_ep_telemetry: true`
4. Create a separate saved search for `WRITE_DISCIPLINE_VIOLATION`
5. Create a separate saved search for `EVENT_PERSISTENCE_FAILED`

### Vercel Log Drain

If deployed on Vercel, configure a log drain to your observability platform (Datadog, Axiom, etc.) to capture all structured logs from serverless function invocations.
