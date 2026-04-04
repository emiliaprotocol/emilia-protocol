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

### 10. Binding Security Check Rates (New — 2026-04-04)

**Why**: Migrations 069–071 added DB-authoritative security checks inside the `verify_handshake_writes` RPC. These checks produce structured log fields that reveal attack signals and operational anomalies that are invisible in higher-level verification outcome metrics.

**Metric**: Count of each error code, grouped by 5-minute window.

**Error codes to track and their significance**:

| Code | Source | Normal rate | Alert threshold | What it means |
|---|---|---|---|---|
| `nonce_required` | `lib/handshake/bind.js` | 0 | Any > 0 in 1h: **S3** | Caller sent a verify request without supplying the binding nonce. Could be: (a) client bug, (b) nonce-omission replay attempt |
| `nonce_mismatch` | `lib/handshake/bind.js` | < 0.1% | > 1% of verifications: **S3** | Provided nonce doesn't match stored value — replay or mutation attempt |
| `payload_hash_required` | `lib/handshake/bind.js` | 0 | Any > 0 in 1h: **S3** | Caller omitted payload hash when binding requires it — same bypass pattern as nonce_required |
| `payload_hash_mismatch` | `lib/handshake/bind.js` | < 0.1% | > 1% of verifications: **S3** | Payload tampered between bind and verify |
| `binding_already_consumed` | `verify_handshake_writes` RPC | < 0.01% | Any > 0 in 1h: **S2** | Replay attempt or double-processing bug; RPC's FOR UPDATE lock neutralized the race |
| `binding_expired` | `verify_handshake_writes` RPC | < 5% | > 20% in 5min: **S3** | Clients taking too long; may indicate a processing bottleneck or clock drift |
| `policy_version_pin_mismatch` | `lib/handshake/verify.js` | 0 | Any > 0: **S3** | A handshake was created against policy version N but the live version changed before verification — indicates a rapid policy rollout during active handshakes |
| `authority_revoked_at_write` | `present_handshake_writes` RPC | 0 | Any > 0: **S2** | Issuer authority was revoked between JS check and DB write; TOCTOU race detected and blocked |
| `authority_expired_at_write` | `present_handshake_writes` RPC | 0 | Any > 0: **S2** | Issuer authority expired between JS check and DB write; same TOCTOU window |

**Source**: Application logs containing the `reason_codes` array from `checkBinding()` and `issuer_status` field from presentation rows.

**Log search pattern** (JSON log aggregation):
```
reason_codes: ["nonce_required" OR "nonce_mismatch" OR "payload_hash_required" OR ...]
issuer_status: ["authority_revoked_at_write" OR "authority_expired_at_write"]
```

### 11. FOR UPDATE Lock Contention (New — 2026-04-04)

**Why**: Migrations 069 and 073 added `SELECT ... FOR UPDATE` inside `verify_handshake_writes` and `present_handshake_writes` RPCs to close TOCTOU races. Under high concurrent load on the same binding, lock waits can accumulate.

**Metric**: Track `verify_handshake` p95/p99 latency during concurrent verify bursts. A sustained rise in p99 with no change in p50 is the contention signature.

**Baseline** (updated from load tests — see `docs/operations/PERFORMANCE_PROOF.md`):
- `verify_handshake` p50: < 300ms, p95: < 1,000ms, p99: < 2,000ms

**Alert threshold**:
- p99 `verify_handshake` > 3,000ms for 2+ minutes: **S3** (potential lock contention)
- `already_consumed` count > 0 alongside latency spike: **S2** (concurrent consume race in progress)

**Note**: Each binding is consumed at most once, so lock contention on a single binding is bounded by the number of concurrent race attempts, not sustained load. Sustained latency elevation points to database resource pressure rather than protocol contention.

### 12. EP-IX Continuity Challenge Monitoring (New — 2026-04-04)

**Why**: The EP-IX rate-limit guard (max 5 open challenges per claim) and self-contest guard are security controls. Hitting either guard in production indicates either an attack or a client bug.

**Metric**: Count of EP-IX guard rejections by type, 1-hour windows.

| Guard | Error code | Alert threshold | What it means |
|---|---|---|---|
| Challenge rate limit | `challenge_rate_limit` | > 10 in 1h on same claim: **S3** | Coordinated challenge-spam against a specific continuity claim |
| Self-contest | `self_contest_not_allowed` | Any > 0: **S3** | Client attempting to challenge its own claim (either bug or evasion attempt) |
| Frozen claim resolution | `claim_frozen` | Any in unexpected flow: **S4** | Client not checking claim state before resolving |

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
| nonce_required / nonce_mismatch count | Application logs | S3 |
| payload_hash_required / mismatch count | Application logs | S3 |
| authority_revoked_at_write count | Application logs | S2 |
| authority_expired_at_write count | Application logs | S2 |
| policy_version_pin_mismatch count | Application logs | S3 |
| verify_handshake p99 latency | Telemetry logs | S3 |
| challenge_rate_limit rejections | Application logs | S3 |
| self_contest_not_allowed count | Application logs | S3 |

## Dashboard Recommendations

### Dashboard 1: Protocol Write Pipeline

- Total writes per minute (stacked by command type)
- Error rate per command type (line chart)
- Latency p50/p95/p99 per command type
- Idempotency cache hit rate

### Dashboard 2: Handshake Operations

- Handshake initiations per minute
- Verification success/failure ratio
- Failure breakdown by category (expired, consumed, policy mismatch, nonce_required, policy_version_pin_mismatch)
- Binding consumption latency (p50/p95/p99)
- FOR UPDATE lock contention signal: p99 latency vs p50 divergence

### Dashboard 3: Security and Abuse

- Rate limit rejections per minute by category
- Write-guard violations (should always be zero)
- Abuse pattern triggers by pattern type
- API key authentication failures by error code (`key_not_found`, `key_revoked`, `entity_inactive`)
- Binding security check rejections: nonce_required, payload_hash_required, nonce_mismatch (should all be zero in steady state)
- Issuer authority TOCTOU rejections: authority_revoked_at_write, authority_expired_at_write
- EP-IX guard rejections: challenge_rate_limit, self_contest_not_allowed

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
