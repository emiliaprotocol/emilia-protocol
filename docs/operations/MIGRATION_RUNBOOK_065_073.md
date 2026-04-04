# Migration Runbook: 065–073

This runbook covers the ordered rollout for migrations 065 through 073, which together close all protocol-level security gaps identified in the L99 hardening audit (2026-04-02 through 2026-04-04). Apply them in sequence; do not skip or reorder.

---

## Overview

| # | Migration | Category | Risk | Downtime Required |
|---|---|---|---|---|
| 065 | `handshake_binding_consumption_guard` | TOCTOU fix (binding uniqueness) | Low | None |
| 066 | `handshake_policy_version_pin` | Column addition | Low | None |
| 067 | `continuity_withdrawn_state` | State machine extension | Low | None |
| 068 | `policy_rollouts` | New table | Low | None |
| 069 | `verify_binding_lock` | RPC rewrite (FOR UPDATE) | **Medium** | None |
| 070 | `create_handshake_atomic_version_pin` | RPC rewrite (atomic parameter) | **Medium** | None |
| 071 | `verify_binding_expiry_in_rpc` | RPC rewrite (DB clock expiry) | **Medium** | None |
| 072 | `tenant_scoping_cloud_tables` | Column additions + indexes | Low | None |
| 073 | `present_authority_recheck` | RPC rewrite (FOR UPDATE on authorities) | **Medium** | None |

**None of these migrations require downtime.** All are additive (new columns, new RPCs, new tables) or safely replace existing RPCs in place using `CREATE OR REPLACE FUNCTION`.

---

## Prerequisites

Before starting:

1. Take a database snapshot / point-in-time recovery checkpoint.
2. Confirm you have `supabase db push` access or direct Postgres access with the `service_role` key.
3. Verify the current migration head matches 064 (`key_rotation`): `SELECT filename FROM supabase_migrations.schema_migrations ORDER BY filename DESC LIMIT 1;`
4. Ensure load is at minimum (ideally maintenance window or off-peak hours) before applying 069–073.
5. Run the full test suite against the current `main` to confirm baseline: `npm test` → all 3277 passing.

---

## Migration-by-Migration Instructions

---

### 065 — Handshake Binding Consumption Guard

**File**: `065_handshake_binding_consumption_guard.sql`
**What it does**: Adds a `UNIQUE` constraint and/or trigger to `handshake_bindings` to guarantee at-most-one consumption atomically. Closes the TOCTOU window between JS-side consumed_at check and UPDATE.
**Why it must come first**: Migrations 069 builds on this foundation. 065 provides the DB-level uniqueness guarantee; 069 provides the RPC-level locking. Both are needed.

**Apply**:
```bash
supabase db push --include-all 2>&1 | grep "065_"
# or directly:
psql $DATABASE_URL < supabase/migrations/065_handshake_binding_consumption_guard.sql
```

**Verify**:
```sql
-- Confirm unique constraint or trigger exists on handshake_bindings
SELECT constraint_name FROM information_schema.table_constraints
WHERE table_name = 'handshake_bindings' AND constraint_type = 'UNIQUE';
```

**Rollback**: Drop the unique constraint or trigger added. No data is mutated.

---

### 066 — Handshake Policy Version Pin

**File**: `066_handshake_policy_version_pin.sql`
**What it does**: Adds `policy_version_number INTEGER` column to the `handshakes` table.
**Impact**: Additive column with `IF NOT EXISTS`. Existing rows get `NULL` (backward compatible). New handshakes will have this populated via migration 070.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/066_handshake_policy_version_pin.sql
```

**Verify**:
```sql
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name = 'handshakes' AND column_name = 'policy_version_number';
```

**Rollback**: `ALTER TABLE handshakes DROP COLUMN IF EXISTS policy_version_number;`

---

### 067 — Continuity Withdrawn State

**File**: `067_continuity_withdrawn_state.sql`
**What it does**: Extends the `continuity_claims.status` CHECK constraint to include `'withdrawn'` and `'frozen_pending_dispute'`. Adds `withdrawn_at`, `withdrawn_by`, and `dispute_id` columns.
**Impact**: Dropping and recreating the CHECK constraint is instant on Postgres 14+. No rows are mutated.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/067_continuity_withdrawn_state.sql
```

**Verify**:
```sql
SELECT constraint_name, check_clause
FROM information_schema.check_constraints
WHERE constraint_name = 'continuity_claims_status_check';
-- Should include 'withdrawn' and 'frozen_pending_dispute' in the IN list
```

**Rollback**: Re-apply the old CHECK constraint without `'withdrawn'` and `'frozen_pending_dispute'`. Only safe if no rows have these values yet.

---

### 068 — Policy Rollouts Table

**File**: `068_policy_rollouts.sql`
**What it does**: Creates `policy_rollouts` table for tracking policy version deployments per environment. Used by `POST /api/cloud/policies/{policyId}/rollout`.
**Impact**: New table, no effect on existing tables.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/068_policy_rollouts.sql
```

**Verify**:
```sql
SELECT table_name FROM information_schema.tables WHERE table_name = 'policy_rollouts';
```

**Rollback**: `DROP TABLE IF EXISTS policy_rollouts;`

---

### 069 — Verify Binding Lock (FOR UPDATE)

**File**: `069_verify_binding_lock.sql`
**What it does**: Rewrites `verify_handshake_writes` RPC to `SELECT ... FOR UPDATE` on the binding row before any state change. Returns `{ok: false, already_consumed: true}` if the race was lost.
**Risk level**: **Medium.** `CREATE OR REPLACE FUNCTION` is transactional. If the new RPC has a bug, all `verify_handshake` calls will fail until the old version is restored.

**Pre-apply check**: Run the test suite against a staging database with this migration applied before applying to production.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/069_verify_binding_lock.sql
```

**Verify**:
```sql
-- Confirm function exists with FOR UPDATE
SELECT prosrc FROM pg_proc WHERE proname = 'verify_handshake_writes'
  AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
-- Should contain "FOR UPDATE" in the function body
```

**Smoke test** (run immediately after apply):
```bash
# Attempt a verify on a known good handshake
curl -X POST https://your-ep.example.com/api/handshake/{id}/verify \
  -H "Authorization: Bearer ep_live_..." \
  -H "Content-Type: application/json" -d '{}'
# Expect: 200 (or 409 if already consumed)
```

**Rollback**: Restore the previous `verify_handshake_writes` function body from migration 060. Keep rollback SQL ready before applying.

---

### 070 — Create Handshake Atomic Version Pin

**File**: `070_create_handshake_atomic_version_pin.sql`
**What it does**: Adds `p_policy_version_number INTEGER DEFAULT NULL` parameter to `create_handshake_atomic` RPC. The version number is now written in the same INSERT as the handshake row — no separate UPDATE step.
**Dependency**: Requires 066 (the `policy_version_number` column) to exist first.
**Risk level**: **Medium.** Same `CREATE OR REPLACE` considerations as 069.

**Ordering constraint**: Apply 066 before 070.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/070_create_handshake_atomic_version_pin.sql
```

**Verify**:
```sql
SELECT proargnames FROM pg_proc WHERE proname = 'create_handshake_atomic'
  AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
-- Should include 'p_policy_version_number'
```

**Smoke test**:
```bash
# Create a new handshake via the API and verify policy_version_number is set
curl -X POST https://your-ep.example.com/api/handshake \
  -H "Authorization: Bearer ep_live_..." \
  -H "Content-Type: application/json" \
  -d '{"mode":"mutual","policy_id":"...","parties":[...],"action_type":"connect","resource_ref":"..."}'
# Then query: SELECT policy_version_number FROM handshakes WHERE handshake_id = '{id}';
# Should be non-null
```

**Rollback**: Restore the previous `create_handshake_atomic` function (remove the `p_policy_version_number` parameter). The column in `handshakes` can remain.

---

### 071 — Verify Binding Expiry in RPC

**File**: `071_verify_binding_expiry_in_rpc.sql`
**What it does**: Adds a `now() > expires_at` check inside `verify_handshake_writes` (under the FOR UPDATE lock). Returns `{ok: false, binding_expired: true}` using the authoritative DB clock instead of the JS clock.
**Dependency**: 069 must already be applied (the FOR UPDATE block is extended, not replaced).
**Risk level**: **Medium.** This changes expiry semantics: DB clock is now authoritative. Any JS-side clocks that were slightly ahead of the DB clock will now see a small number of bindings that were "passing" in JS start failing at the RPC level. This is correct behavior, not a regression.

**Ordering constraint**: Apply 069 before 071.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/071_verify_binding_expiry_in_rpc.sql
```

**Verify**:
```sql
SELECT prosrc FROM pg_proc WHERE proname = 'verify_handshake_writes'
  AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
-- Should contain both "FOR UPDATE" and "binding_expired" in the function body
```

**Monitor after apply**: Watch `binding_expired` counts in application logs for the first 30 minutes. A small uptick (< 2%) is expected if there was client-side clock skew. A large spike (> 5%) indicates a configuration issue with binding TTLs or systematic clock drift.

**Rollback**: Restore the 069 version of `verify_handshake_writes` (without the expiry check). Clients will fall back to JS-clock expiry.

---

### 072 — Tenant Scoping Cloud Tables

**File**: `072_tenant_scoping_cloud_tables.sql`
**What it does**: Adds `tenant_id UUID` columns to `signoff_challenges`, `signoff_attestations`, `handshake_policies`, and `policy_versions`. Adds indexes on `tenant_id` for each. Existing rows get `NULL`.
**Impact**: Additive. Cloud routes already filter by `auth.tenantId` — the new column enables DB-level scoping.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/072_tenant_scoping_cloud_tables.sql
```

**Verify**:
```sql
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name = 'tenant_id'
  AND table_name IN ('signoff_challenges', 'signoff_attestations', 'handshake_policies', 'policy_versions');
-- Should return 4 rows
```

**Rollback**: Drop the `tenant_id` columns and indexes from each table. Safe if no rows have been written with `tenant_id` values yet.

---

### 073 — Present Authority Recheck (FOR UPDATE on authorities)

**File**: `073_present_authority_recheck.sql`
**What it does**: Rewrites `present_handshake_writes` RPC to re-check issuer authority status under `SELECT ... FOR UPDATE` when `p_verified = TRUE`. Overrides `p_verified` to `FALSE` and sets `issuer_status` to `'authority_revoked_at_write'` or `'authority_expired_at_write'` if the authority was revoked or expired between the JS check and the RPC write.
**Risk level**: **Medium.** `CREATE OR REPLACE FUNCTION`. If the authority row doesn't exist (no authority for this issuer), the SELECT returns no rows and the function proceeds without modification — safe fallback.

**Apply**:
```bash
psql $DATABASE_URL < supabase/migrations/073_present_authority_recheck.sql
```

**Verify**:
```sql
SELECT prosrc FROM pg_proc WHERE proname = 'present_handshake_writes'
  AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
-- Should contain "FOR UPDATE" and "authority_revoked_at_write"
```

**Smoke test**: Revoke an authority and immediately attempt to present a handshake using that authority via the API. The presentation should succeed (record inserted) but with `verified=false` and `issuer_status='authority_revoked_at_write'`. Without this migration, it would be recorded as `verified=true`.

**Monitor after apply**: Check `issuer_status` field distribution in `handshake_presentations` for the first hour. Any `authority_revoked_at_write` or `authority_expired_at_write` values indicate the TOCTOU protection fired. These are security events — alert at **S2** (see OBSERVABILITY.md §10).

**Rollback**: Restore the previous `present_handshake_writes` function body from migration 062.

---

## Full Sequence Summary

```
065  →  066  →  067  →  068  →  069  →  070  →  071  →  072  →  073
```

**Hard ordering constraints:**
- 066 before 070 (column must exist before RPC uses it)
- 069 before 071 (FOR UPDATE block must exist before expiry check is added to it)
- 065 before 069 (DB uniqueness before RPC-level locking)

All other migrations may be applied concurrently if your migration tooling supports parallel DDL, though sequential application is safest.

---

## Post-Migration Verification

After all 9 migrations are applied, run the full protocol test suite:

```bash
npm test
# Expected: 3277 passing, 0 failing
```

Then run the smoke test sequence:
1. Create a handshake → verify `policy_version_number` is set in DB
2. Attempt concurrent verify on same binding → verify only 1 succeeds
3. Attempt verify on expired binding → verify `binding_expired` is returned
4. Attempt presentation with revoked authority → verify `authority_revoked_at_write` is set
5. Check `OBSERVABILITY.md` §10 alert baseline values against actual logs for first hour

---

## Rollback Strategy

If a critical regression is detected after apply:

1. **For RPC rewrites (069, 070, 071, 073)**: Run the rollback SQL (restore previous function body from the prior migration file). RPC rewrites are instant — no data migration needed.
2. **For column additions (066, 072)**: Drop the columns. Only safe if no new rows have been written with these columns populated.
3. **For new tables (068)**: `DROP TABLE policy_rollouts;` — safe if no rollout records have been created.
4. **For constraint changes (067)**: Re-apply the old CHECK constraint. Safe if no rows have been set to `'withdrawn'` or `'frozen_pending_dispute'`.
5. **For uniqueness guards (065)**: Drop the added constraint or trigger.

**After any rollback**: File an incident report, capture the failing test case, and do not re-apply until the root cause is fixed and a new test is added.

---

*Last updated: 2026-04-04 — Migrations 065–073 applied in sequence during L99 hardening audit.*
