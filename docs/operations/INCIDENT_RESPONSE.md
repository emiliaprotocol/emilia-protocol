# EMILIA Protocol -- Incident Response

## Severity Classification

| Severity | Definition | Response Time | Examples |
|---|---|---|---|
| **S1 -- Critical** | Trust system integrity compromised. Unauthorized writes possible or detected. | Immediate (< 15 min) | Service role key compromise, write-guard bypass, event store corruption |
| **S2 -- High** | Trust system degraded. Incorrect trust decisions possible. | < 1 hour | Double consumption detected, policy resolution cascade failure, commit signing key compromise |
| **S3 -- Medium** | Operational degradation. Trust system functional but impaired. | < 4 hours | Rate limiter backend offline, blockchain anchoring failure, abuse detection false positives |
| **S4 -- Low** | Minor issue. No trust impact. | < 24 hours | Health check reporting degraded, non-critical cron failure, telemetry emission failure |

## Incident Response Procedures

### 1. Key Compromise

See `docs/operations/KEY_MANAGEMENT.md` for detailed per-key procedures. Summary:

**API Key (`ep_live_*`)** -- Severity S2:
1. Revoke the key immediately (`revoked_at` on `api_keys` record).
2. Issue replacement key.
3. Audit `protocol_events` for unauthorized writes from the compromised entity.

**Service Role Key (`SUPABASE_SERVICE_ROLE_KEY`)** -- Severity S1:
1. Rotate in Supabase dashboard immediately.
2. Redeploy with new key.
3. Audit for direct database modifications bypassing `protocolWrite()`.
4. Run `npm run reconstitute` to verify projection consistency.

**Commit Signing Key (`EP_COMMIT_SIGNING_KEY`)** -- Severity S2:
1. Generate new keypair, rotate environment variables, redeploy.
2. Remove compromised public key from `EP_COMMIT_SIGNING_KEYS`.
3. Audit commits signed during compromise window.

### 2. Write-Path Bypass Detection

**Severity: S1**

A write-path bypass means trust-bearing data was written to a protected table without going through `protocolWrite()`. This breaks the event log guarantee.

**Detection signals**:
- Records in trust tables (`receipts`, `commits`, `disputes`, etc.) with no corresponding entry in `protocol_events`
- `WRITE_DISCIPLINE_VIOLATION` errors in logs from `lib/write-guard.js`
- CI failure on `npm run check:protocol` indicating a route handler imports `getServiceClient()` instead of `getGuardedClient()`

**Response**:
1. **Contain**: If a route is writing directly, take the route offline or deploy a hotfix that switches to `getGuardedClient()`.
2. **Assess**: Query for orphaned records (trust table rows without corresponding `protocol_events` entries):
   ```sql
   -- Example: find receipts without a protocol event
   SELECT r.receipt_id
   FROM receipts r
   LEFT JOIN protocol_events pe
     ON pe.aggregate_type = 'receipt'
     AND pe.aggregate_id = r.receipt_id::text
   WHERE pe.event_id IS NULL;
   ```
3. **Remediate**: For each orphaned record, determine whether the write was legitimate. If legitimate, create a backfill protocol event. If illegitimate, revert the state change and file internal incident report.
4. **Prevent**: Run `npm run check:protocol` in CI to catch future violations. Verify the write guard is active on all route handlers.

### 3. Event Store Corruption

**Severity: S1**

The `protocol_events` and `handshake_events` tables are append-only. Database triggers prevent UPDATE and DELETE. Corruption means one of:
- Events were modified or deleted (trigger bypassed or disabled)
- Events contain incorrect `payload_hash` values
- The `parent_event_hash` chain is broken for an aggregate

**Detection signals**:
- `npm run reconstitute` produces projections that differ from current state
- Hash verification failures when auditing the event chain
- Missing events for known state transitions

**Response**:
1. **Contain**: Verify that append-only triggers are still active on both tables. Re-enable if disabled.
2. **Assess**: Run `npm run reconstitute` to replay all events and compare the resulting projection against current table state.
3. **Identify scope**: Determine which aggregates have inconsistencies and the time window.
4. **Remediate**:
   - If projections diverged from events: rebuild projections from the event log (the event log is the source of truth).
   - If events themselves are corrupted: cross-reference with blockchain anchors (if anchoring is enabled) to identify the last known-good state.
5. **Report**: This is a regulatory-reportable incident. Document the scope, root cause, and remediation in a post-incident report.

### 4. Double Consumption Detection

**Severity: S2**

A handshake binding should be consumed exactly once. Double consumption means the `consumed_at IS NULL` guard in `_handleVerifyHandshake` was bypassed, or a race condition occurred.

**Detection signals**:
- Multiple `handshake_consumptions` records for the same `binding_id`
- `verified` handshake events for a binding that already has `consumed_at` set
- The hard gate at the top of `_handleVerifyHandshake` logged a rejection but downstream processing continued

**Response**:
1. **Assess**: Query `handshake_consumptions` for duplicate `binding_id` entries:
   ```sql
   SELECT binding_id, COUNT(*) as consumption_count
   FROM handshake_consumptions
   GROUP BY binding_id
   HAVING COUNT(*) > 1;
   ```
2. **Identify impact**: For each double-consumed binding, identify the downstream action that was authorized. Determine if two distinct actions were authorized by the same binding.
3. **Remediate**: If a duplicate action was authorized, the second action lacks a valid trust basis. Flag it for review and potentially reverse its effects.
4. **Prevent**: Review the binding consumption code path for race conditions. The `consumed_at IS NULL` filter on the UPDATE statement should prevent this at the database level.

### 5. Policy Resolution Failure Cascade

**Severity: S2**

Policy resolution (`lib/handshake/policy.js`) is fail-closed. If policy cannot be loaded, handshakes are rejected. A cascade failure means many handshakes are failing simultaneously due to a systemic policy loading issue.

**Detection signals**:
- Spike in `policy_load_failed` or `policy_not_found` errors in logs
- High rate of handshake verification rejections
- `resolvePolicy()` throwing errors consistently

**Response**:
1. **Diagnose**: Check database connectivity. Policy resolution queries `handshake_policies` table.
2. **Check for data issues**: Verify that referenced policies exist and have `status: 'active'`:
   ```sql
   SELECT policy_id, policy_key, version, status
   FROM handshake_policies
   WHERE status = 'active'
   ORDER BY policy_key, version DESC;
   ```
3. **If database is down**: This is a broader infrastructure incident. Rate limiting will fail-close on write categories, limiting blast radius.
4. **If policies were accidentally deleted/deactivated**: Restore from backup. Policy resolution failure is fail-closed by design -- no handshakes proceed without a valid policy.
5. **Temporary mitigation**: There is no bypass. This is intentional. Policy resolution must succeed for handshakes to proceed.

## Investigation Tools

### Protocol Event Log

The `protocol_events` table is the primary investigation tool. Every trust-changing write produces an event.

Key columns:
- `event_id`: unique event identifier
- `aggregate_type`: `receipt`, `commit`, `dispute`, `report`, `handshake`
- `aggregate_id`: the entity's ID for this aggregate
- `command_type`: which of the 17 command types produced this event
- `payload_hash`: SHA-256 of the canonical input payload
- `actor_authority_id`: who performed the action
- `idempotency_key`: SHA-256 of `type:actor:input` for dedup detection
- `created_at`: timestamp

### Handshake Event Log

The `handshake_events` table tracks handshake-specific lifecycle events.

Key columns:
- `handshake_id`: which handshake
- `event_type`: `initiated`, `presentation_added`, `status_changed`, `verified`, `rejected`, `expired`, `revoked`
- `actor_entity_ref`: who triggered the event
- `detail`: JSON detail payload

### Reconstitution Script

```bash
npm run reconstitute
# Runs: node scripts/replay-protocol.js --reconstitute
```

This replays all `protocol_events` in order and rebuilds the current-state projections. Use it to:
- Verify that current state matches the event log
- Recover from projection corruption
- Audit the full history of any aggregate

### Telemetry Logs

`protocolWrite()` emits structured JSON logs with `_ep_telemetry: true`:

```json
{
  "_ep_telemetry": true,
  "event_id": "...",
  "command_type": "submit_receipt",
  "aggregate_type": "receipt",
  "aggregate_id": "...",
  "actor": "...",
  "duration_ms": 145,
  "timestamp": "2026-03-20T..."
}
```

Filter logs by `_ep_telemetry` to isolate protocol write telemetry from other application logs.

## Communication Templates

### Internal Notification (S1/S2)

```
INCIDENT: [Brief description]
SEVERITY: S[1|2]
DETECTED: [timestamp]
IMPACT: [What trust guarantees are affected]
STATUS: [Investigating | Mitigating | Resolved]
ACTIONS TAKEN: [List actions]
NEXT STEPS: [List next steps]
```

### External Notification (if entity data is affected)

```
We detected an issue with [brief description] affecting [scope].
Time window: [start] to [end].
Impact: [What was affected, in plain language].
Actions taken: [What we did to resolve it].
Your action required: [If any, e.g., "rotate your API key"].
```

## Post-Incident Review Process

1. **Timeline**: Reconstruct the full timeline from detection to resolution using `protocol_events`, application logs, and deployment history.
2. **Root cause**: Identify the root cause. Was it a code defect, configuration error, infrastructure failure, or security breach?
3. **Impact assessment**: Quantify the impact: how many entities affected, how many trust-changing writes were impacted, was the event log compromised?
4. **Remediation verification**: Confirm that the fix is deployed and the incident is fully resolved. Run `/api/health` and `npm run reconstitute` to verify.
5. **Prevention**: Identify what changes (code, process, monitoring) would prevent recurrence.
6. **Documentation**: Write the post-incident report and store it in the internal incident log. For S1 incidents, this may need to be shared with regulatory stakeholders.
