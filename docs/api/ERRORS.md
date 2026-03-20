# EMILIA Protocol -- Error Reference

## Standard Error Format

All EP API errors use RFC 7807 Problem Details, produced by `epProblem()` in `lib/errors.js`.

```json
{
  "type": "https://emiliaprotocol.ai/errors/{code}",
  "title": "Human Readable Code",
  "status": 400,
  "detail": "Specific description of what went wrong"
}
```

| Field | Type | Description |
|---|---|---|
| `type` | string | URI identifying the error type. Pattern: `https://emiliaprotocol.ai/errors/{code}` |
| `title` | string | Human-readable error code (auto-generated from `code` by replacing underscores and capitalizing) |
| `status` | number | HTTP status code |
| `detail` | string | Specific description of this error instance |

Additional fields may be present in the `extras` object (e.g., `details` for conflict errors).

## Error Codes by Category

### Authentication Errors (401)

| Code | Detail | Cause |
|---|---|---|
| `unauthorized` | Missing or invalid API key. Use: Authorization: Bearer ep_live_... | No `Authorization` header, or header does not start with `Bearer ep_` |
| `missing_key` | Missing or invalid API key | Same as above (returned by `authenticateRequest`) |
| `key_not_found` | API key not found | The SHA-256 hash of the provided key does not match any record in `api_keys` |

### Authorization Errors (403)

| Code | Detail | Cause |
|---|---|---|
| `forbidden` | {reason} | The authenticated entity lacks permission for the requested action |
| `key_revoked` | API key revoked | The API key exists but has `revoked_at` set. The entity must obtain a new key |
| `entity_inactive` | Entity is inactive or suspended | The entity linked to the API key has `status` other than `active` |

### Validation Errors (400)

| Code | Detail | Cause |
|---|---|---|
| `bad_request` | {reason} | Generic validation failure. The `detail` field describes what is wrong |
| `VALIDATION_ERROR` | {field} is required | A required field is missing from the command input. Thrown by command-specific validators in `protocolWrite()` |
| `INVARIANT_VIOLATION` | command.type is required / command.input must be an object | Protocol-level structural invariant violated |
| `UNKNOWN_COMMAND_TYPE` | Unknown command type: "{type}" | The `command.type` is not one of the 17 valid COMMAND_TYPES |

### Not Found Errors (404)

| Code | Detail | Cause |
|---|---|---|
| `not_found` | {what} not found | The requested entity, receipt, dispute, commit, or handshake does not exist |

### Conflict Errors (409)

| Code | Detail | Cause |
|---|---|---|
| `conflict` | {reason} | The operation conflicts with existing state (e.g., duplicate entity registration, receipt already confirmed) |

### Rate Limiting Errors (429)

| Code | Detail | Cause |
|---|---|---|
| `rate_limited` | Rate limit exceeded. Try again later. | The entity or IP has exceeded the rate limit for this endpoint category |
| `ABUSE_DETECTED` | Action blocked by abuse detection: {pattern} | The abuse detection layer in `protocolWrite()` blocked the action. Patterns: `repeated_identical_reports`, `brigading`, `ip_report_flooding`, `retaliatory_filing`, `dispute_flooding` |

Rate limit responses include headers:
```
X-RateLimit-Limit: {max requests in window}
X-RateLimit-Remaining: 0
X-RateLimit-Reset: {seconds until window resets}
Retry-After: {seconds until window resets}
```

### Gone Errors (410)

| Code | Detail | Cause |
|---|---|---|
| `gone` | {reason} | The resource existed but has been permanently removed or expired |

### Internal Errors (500)

| Code | Detail | Cause |
|---|---|---|
| `internal_error` | Internal server error | Unhandled server error. No details exposed to prevent information leakage |
| `malformed_key_record` | Internal error during authentication | The API key record in the database is missing or has an invalid `entity_id` |
| `health_check_failed` | Health check response assembly failed | The `/api/health` endpoint itself failed to build its response |

### Service Unavailable (503)

| Code | Detail | Cause |
|---|---|---|
| `auth_service_unavailable` | Authentication service unavailable | Database error during API key lookup or entity lookup. Returned instead of masquerading as "invalid key" |
| `rate_limit_unavailable` | Service temporarily unavailable -- rate limiting backend offline | Upstash Redis is unreachable and this endpoint's rate limit category is fail-closed (`submit`, `dispute_write`, `register`, `anchor`) |

## Protocol Write Errors

These errors are thrown (not returned as HTTP responses) by `protocolWrite()` and its pipeline. Route handlers catch them and convert to HTTP responses.

### ProtocolWriteError (from `lib/protocol-write.js`)

| Code | Status | Cause |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Command input fails type-specific validation |
| `INVARIANT_VIOLATION` | 400 | Protocol-level structural invariant violated |
| `UNKNOWN_COMMAND_TYPE` | 400 | Command type is not in COMMAND_TYPES |
| `ABUSE_DETECTED` | 429 | Abuse detection blocked the action |
| `NO_HANDLER` | 500 | No handler registered for this command type (should never occur if invariant check passes) |
| `EVENT_PERSISTENCE_FAILED` | 500 | Failed to write to `protocol_events` table. The state transition is REJECTED. This is a hard failure -- an unlogged trust-changing transition is never acceptable |

### ProtocolWriteError (from `lib/errors.js`)

| Code | Status | Cause |
|---|---|---|
| `PROTOCOL_WRITE_FAILED` | 500 | Generic trust-bearing write failure. Covers receipt creation, commit storage, dispute filing/resolution |

### TrustEvaluationError (from `lib/errors.js`)

| Code | Status | Cause |
|---|---|---|
| `TRUST_EVALUATION_FAILED` | 500 | Trust evaluation failed in a context where it must not be skipped (commit issuance, policy gating) |

## Write Discipline Violations

These are runtime errors thrown by the write guard (`lib/write-guard.js`). They indicate a code defect where a route handler attempted to directly mutate a trust table.

**Error message pattern**:
```
WRITE_DISCIPLINE_VIOLATION: Direct {operation}() on trust table "{table}" is forbidden.
All trust-bearing writes MUST go through protocolWrite().
This is a runtime enforcement -- not a convention.
```

**Operations blocked**: `insert`, `update`, `upsert`, `delete`

**Tables protected** (from `lib/write-guard.js`):
- `receipts`, `commits`, `disputes`, `trust_reports`
- `protocol_events`
- `handshakes`, `handshake_parties`, `handshake_presentations`
- `handshake_bindings`, `handshake_results`, `handshake_policies`
- `handshake_events`, `handshake_consumptions`

Any occurrence of this error in production logs is an **S1 incident**.

## Binding Invariant Violations

These errors occur during handshake operations when replay prevention or policy binding invariants are violated.

| Error | Cause |
|---|---|
| `binding_expired` | Binding TTL exceeded. TTL is clamped to [60s, 1800s] |
| `binding_already_consumed` | Binding's `consumed_at` is already set. One-time use enforced |
| `policy_hash_mismatch` | Policy rules hash at verification time differs from hash at initiation time. Policy changed during the handshake |
| `policy_not_found` | Policy referenced by `policy_id` does not exist |
| `policy_load_failed` | Database error while loading policy |
| `nonce_missing` | Binding requires a nonce but none was provided |

## Event Persistence Failures

When `appendProtocolEvent()` fails, the error message follows this pattern:

```
EVENT_WRITE_REQUIRED: Failed to persist protocol event for {command_type}
on {aggregate_type}/{aggregate_id}: {db_error_message}.
State transition REJECTED -- every transition must be logged.
```

This is a hard failure. The entire `protocolWrite()` operation is rejected. The trust-changing state transition does not proceed. This is intentional: an unlogged trust-changing transition is never acceptable.

## Dispute State Machine Errors

Invalid state transitions are rejected by `validateTransition()` in `lib/procedural-justice.js`.

**Valid dispute states and transitions**:

| Current State | Valid Transitions |
|---|---|
| `open` | `under_review`, `withdrawn` |
| `under_review` | `upheld`, `reversed`, `dismissed`, `appealed` |
| `upheld` | `appealed` |
| `reversed` | `appealed` |
| `dismissed` | `appealed` |
| `appealed` | `appeal_upheld`, `appeal_reversed`, `appeal_dismissed` |
| `appeal_upheld` | (terminal) |
| `appeal_reversed` | (terminal) |
| `appeal_dismissed` | (terminal) |
| `withdrawn` | (terminal) |

Invalid transition error: `Invalid transition: '{current}' -> '{target}'. Valid: {valid_transitions}`
Terminal state error: `State '{state}' is terminal -- no transitions allowed`
