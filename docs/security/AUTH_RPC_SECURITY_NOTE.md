# Auth RPC Security Note

**Date:** 2026-03-28
**Change:** `resolve_authenticated_actor()` Postgres RPC replaces 3 serial REST API calls

---

## What Changed

The authentication path was optimized from 3 serial Supabase REST API calls to 1 RPC call:

```
Before: api_keys SELECT → api_keys UPDATE → entities SELECT  (3 roundtrips, ~240ms)
After:  resolve_authenticated_actor RPC                       (1 roundtrip, ~40ms)
```

## What Did NOT Change

### Identity comes from auth, not from request body

The authenticated entity is resolved from the API key hash via DB lookup. The caller cannot forge, override, or inject an entity identity through request parameters. This invariant is unchanged.

### Revocation is immediate

The RPC checks `revoked_at` on every request. There is no cache layer between the key presentation and the revocation check. A revoked key fails on the very next request. This invariant is unchanged.

### Fail-closed on error

| Scenario | Result | Status |
|----------|--------|--------|
| Key not found | Auth failed | 401 |
| All keys revoked | Auth failed | 401 |
| Entity inactive | Auth failed | 401 |
| Malformed key record | Internal error | 500 |
| RPC call fails | Service unavailable | 503 |
| Null RPC response | Auth failed | 401 |

No error path returns a valid entity. Every failure mode returns an error status. This invariant is unchanged.

### Scope propagation

Permissions returned by the RPC are the raw `permissions` JSONB from the `api_keys` table. No default permissions are injected. Empty permissions (`[]`) remain empty. Null permissions remain null. This invariant is unchanged.

### Entity isolation

Each API key maps to exactly one entity. Different keys return different entities. There is no cross-entity leakage. The RPC uses the same `key_hash → entity_id → entities` join path as the original code.

## Test Coverage

16 automated tests in `tests/auth-rpc.test.js` covering:

- Header validation (missing, wrong prefix, empty)
- RPC error handling (503 on failure, null data)
- Key not found (401)
- Revoked key (401, no entity leaked)
- Inactive entity (401)
- Malformed record (500, fail closed)
- Successful auth (entity + permissions)
- Entity isolation (different keys, different entities)
- Scope propagation (empty/null preserved)
- Identity from DB, not forgeable

## RPC Function

```sql
CREATE FUNCTION resolve_authenticated_actor(p_key_hash TEXT)
RETURNS JSONB
```

- `SECURITY DEFINER` — runs with the function owner's privileges
- Counts active vs revoked keys
- Returns first active key's entity + permissions
- Updates `last_used_at` inside the same transaction
- Returns structured error JSON on failure (never leaks entity data)
