# EP Error Code Reference

Every EP API response that indicates failure uses a structured error envelope:

```json
{
  "error": {
    "code": "EP-3001",
    "message": "Handshake not found",
    "detail": "No handshake with id abc-123",
    "timestamp": "2025-05-01T12:00:00.000Z"
  }
}
```

| Field       | Type   | Description                                         |
|-------------|--------|-----------------------------------------------------|
| `code`      | string | Machine-readable code (`EP-NNNN`). Stable across versions. |
| `message`   | string | Short, constant description of the error class.      |
| `detail`    | string | (Optional) Human-readable specifics for this occurrence. |
| `timestamp` | string | ISO 8601 timestamp of when the error was generated.  |

Clients should match on `code`, not on `message` or `detail`.

---

## Auth and Identity (1xxx)

| Code      | HTTP | Message                                          | When Returned                                                     | Client Action                                |
|-----------|------|--------------------------------------------------|-------------------------------------------------------------------|----------------------------------------------|
| `EP-1001` | 401  | Authentication required                          | No `Authorization` header, or bearer token is missing/malformed.  | Include `Authorization: Bearer ep_live_...`. |
| `EP-1002` | 403  | Insufficient permissions                         | Token is valid but the caller lacks the required role or scope.    | Request elevated permissions or use a different key. |
| `EP-1003` | 403  | Caller is not authorized for this operation      | Ownership or delegation check failed for the requested resource.  | Ensure you own the entity or hold a valid delegation. |
| `EP-1004` | 404  | Identity not found                               | Identity lookup returned no match for the given reference.        | Verify the identity reference is correct.    |
| `EP-1005` | 404  | Principal not found                              | No principal exists for the given `principalId`.                  | Register the principal first.                |
| `EP-1006` | 403  | Delegation is invalid or out of scope            | Delegation exists but is expired, revoked, or doesn't cover the action. | Request a new delegation or broaden scope. |
| `EP-1007` | 404  | Delegation not found                             | No delegation exists for the given `delegation_id`.               | Create a delegation via `POST /api/delegations/create`. |

## Input Validation (2xxx)

| Code      | HTTP | Message               | When Returned                                                       | Client Action                              |
|-----------|------|-----------------------|---------------------------------------------------------------------|--------------------------------------------|
| `EP-2001` | 400  | Invalid input         | Request body failed schema validation.                              | Check the `detail` field for specifics; fix and retry. |
| `EP-2002` | 400  | Missing required field| A required field is absent. `detail` names the field.               | Add the missing field and retry.           |
| `EP-2003` | 400  | Invalid action type   | `action_type` is not one of `install, connect, delegate, transact`. | Use a valid action type.                   |
| `EP-2004` | 400  | Invalid reason value  | Dispute `reason` is not in the allowed set.                         | Check allowed values in API docs.          |
| `EP-2005` | 400  | Invalid format        | A field value is syntactically wrong (e.g. bad ISO 8601 timestamp). | Fix the format per the field spec.         |

## Handshake Lifecycle (3xxx)

| Code      | HTTP | Message                            | When Returned                                                         | Client Action                                |
|-----------|------|------------------------------------|-----------------------------------------------------------------------|----------------------------------------------|
| `EP-3001` | 404  | Handshake not found                | No handshake exists for the given `handshakeId`.                      | Verify the ID; initiate a new handshake.     |
| `EP-3002` | 409  | Handshake binding already consumed | The handshake binding was already used in a prior gate/commit cycle.   | Initiate a new handshake.                    |
| `EP-3003` | 409  | Invalid state transition           | The handshake is not in a state that allows the requested operation.   | Check handshake `status` before acting.      |
| `EP-3004` | 409  | Binding hash mismatch              | The payload hash presented does not match the binding's expected hash. | Recompute the payload hash.                  |
| `EP-3005` | 410  | Handshake binding expired          | The binding's `expires_at` has passed.                                | Initiate a new handshake.                    |
| `EP-3006` | 409  | Action intent hash mismatch        | The `action_hash` re-computed from the current request differs from initiation. | Do not alter action intent between init and gate. |
| `EP-3007` | 403  | Initiator does not own handshake   | `entity_ref` on the initiator party does not match the authenticated entity. | Use the correct entity credentials.      |
| `EP-3008` | 500  | Handshake initiation failed        | Server-side failure during handshake creation.                        | Retry; if persistent, contact support.       |
| `EP-3009` | 500  | Handshake verification failed      | Server-side failure during handshake evaluation.                      | Retry; if persistent, contact support.       |

## Signoff and Attestation (4xxx)

| Code      | HTTP | Message                       | When Returned                                                     | Client Action                                |
|-----------|------|-------------------------------|-------------------------------------------------------------------|----------------------------------------------|
| `EP-4001` | 404  | Challenge not found           | No signoff challenge exists for the given `challengeId`.          | Verify the ID; issue a new challenge.        |
| `EP-4002` | 410  | Challenge expired             | The challenge's `expiresAt` has passed.                           | Issue a new challenge.                       |
| `EP-4003` | 400  | Invalid authentication method | `authMethod` is not recognized.                                   | Use `api_key`, `oauth`, or another supported method. |
| `EP-4004` | 403  | Insufficient assurance level  | The assurance level provided does not meet the policy requirement. | Escalate to a higher-assurance auth method.  |
| `EP-4005` | 500  | Signoff attestation failed    | Server-side failure during attestation creation.                  | Retry; if persistent, contact support.       |
| `EP-4006` | 500  | Challenge issuance failed     | Server-side failure during challenge creation.                    | Retry; if persistent, contact support.       |

## Policy and Trust Evaluation (5xxx)

| Code      | HTTP | Message                                      | When Returned                                                             | Client Action                                |
|-----------|------|----------------------------------------------|---------------------------------------------------------------------------|----------------------------------------------|
| `EP-5001` | 404  | Policy not found                             | Named policy does not exist.                                              | Use `GET /api/policies` to list available policies. |
| `EP-5002` | 409  | Policy version changed                       | The policy hash no longer matches; policy was updated since last read.    | Re-fetch the policy and re-evaluate.         |
| `EP-5003` | 404  | Entity not found in EP registry              | `entity_id` does not exist in EP.                                         | Register the entity first via `POST /api/entities/register`. |
| `EP-5004` | 500  | Trust evaluation failed                      | Canonical evaluator encountered an internal error.                        | Retry; if persistent, contact support.       |
| `EP-5005` | 403  | Action requires trust gate pre-authorization | High-stakes action (`transact`, `connect`) was issued without `gate_ref`. | Call `POST /api/trust/gate` first and pass the returned `commit_ref` as `gate_ref`. |
| `EP-5006` | 403  | Trust gate denied the action                 | The `gate_ref` commit had a `deny` decision.                             | Resolve the deny reasons and re-evaluate.    |
| `EP-5007` | 403  | Invalid gate reference                       | `gate_ref` does not point to a valid commit.                              | Use the `commit_ref` from a successful gate call. |
| `EP-5008` | 403  | Gate was issued for a different entity        | `entity_id` on the gate commit does not match the request.               | Use the correct `gate_ref` for this entity.  |
| `EP-5009` | 403  | Gate was issued for a different action type   | `action_type` on the gate commit does not match the request.             | Use the correct `gate_ref` for this action.  |

## Write Discipline (6xxx)

| Code      | HTTP | Message                    | When Returned                                                           | Client Action                                |
|-----------|------|----------------------------|-------------------------------------------------------------------------|----------------------------------------------|
| `EP-6001` | 500  | Write discipline violation | A route attempted to write via a guarded client instead of `protocolWrite`. | This is a server bug; report it.           |
| `EP-6002` | 500  | Event write required but failed | A trust-critical event (audit log, receipt) could not be persisted.  | Retry; do not proceed without the event.     |
| `EP-6003` | 500  | Protocol write failed      | `protocolWrite()` failed during a trust-bearing operation.              | Retry; if persistent, contact support.       |

## Cloud and Tenant (7xxx)

| Code      | HTTP | Message              | When Returned                                               | Client Action                                |
|-----------|------|----------------------|-------------------------------------------------------------|----------------------------------------------|
| `EP-7001` | 404  | Tenant not found     | Multi-tenant lookup returned no match.                      | Verify your tenant slug / ID.                |
| `EP-7002` | 401  | Invalid API key      | The `ep_live_...` key is malformed, revoked, or unknown.    | Rotate the key in your EP dashboard.         |
| `EP-7003` | 429  | Rate limit exceeded  | Too many requests in the current window.                    | Back off and retry with exponential delay.   |

## Commit and Receipt Lifecycle (8xxx)

| Code      | HTTP | Message                                | When Returned                                                      | Client Action                                |
|-----------|------|----------------------------------------|--------------------------------------------------------------------|----------------------------------------------|
| `EP-8001` | 404  | Commit not found                       | No commit exists for the given `commitId`.                         | Verify the commit ID.                        |
| `EP-8002` | 410  | Commit expired                         | The commit's `expires_at` has passed.                              | Issue a new commit.                          |
| `EP-8003` | 409  | Commit already revoked                 | The commit has already been revoked.                               | No further action possible on this commit.   |
| `EP-8004` | 409  | Commit already fulfilled               | The commit was already fulfilled by a receipt.                     | Use the existing receipt.                    |
| `EP-8005` | 500  | Commit issuance failed                 | Server-side failure during commit creation.                        | Retry; if persistent, contact support.       |
| `EP-8006` | 404  | Receipt not found                      | No receipt exists for the given `receiptId`.                       | Verify the receipt ID.                       |
| `EP-8007` | 409  | Duplicate receipt for this commit      | A receipt already exists for the referenced commit.                | Retrieve the existing receipt.               |
| `EP-8008` | 409  | Dispute already filed for this receipt | A dispute has already been opened against this receipt.            | Check dispute status via `GET /api/disputes/:id`. |
| `EP-8009` | 404  | Dispute not found                      | No dispute exists for the given `disputeId`.                       | Verify the dispute ID.                       |
| `EP-8010` | 500  | Dispute filing failed                  | Server-side failure during dispute filing.                         | Retry; if persistent, contact support.       |

## System and Internal (9xxx)

| Code      | HTTP | Message                            | When Returned                                   | Client Action                                |
|-----------|------|------------------------------------|-------------------------------------------------|----------------------------------------------|
| `EP-9001` | 500  | Internal server error              | Unhandled server exception.                     | Retry; if persistent, contact support.       |
| `EP-9002` | 503  | Database unavailable               | Database connection failed or timed out.        | Retry after a short delay.                   |
| `EP-9003` | 500  | Failed to retrieve trust policies  | Policy listing encountered an internal error.   | Retry; if persistent, contact support.       |

---

## Retry Guidance

| HTTP Status | Retryable? | Strategy                                   |
|-------------|------------|--------------------------------------------|
| 400         | No         | Fix the request.                           |
| 401         | No         | Provide valid credentials.                 |
| 403         | No         | Resolve the authorization issue.           |
| 404         | No         | Verify resource existence.                 |
| 409         | No         | Resolve the conflict (e.g. state mismatch).|
| 410         | No         | Resource is gone; create a new one.        |
| 429         | Yes        | Exponential backoff with jitter.           |
| 500         | Maybe      | Retry once; if it persists, report a bug.  |
| 503         | Yes        | Retry after 1-5 seconds.                   |

## Source Files

- Taxonomy: `lib/errors/taxonomy.js`
- Response builder: `lib/errors/response.js`
- Legacy helpers (still in use): `lib/errors.js`
