<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP Database Isolation — Findings & Plan

**Status:** root-cause investigated 2026-06-29. EP is already data-isolated; the
co-mingling was dead code, now removed. A full project-to-project migration is
**not** required. Contingency runbook included if hard org separation is later
mandated (compliance / blast-radius).

## What was actually true

Earlier work raised "EP's prod DB is shared across products." Investigation
(`list_projects` + schema introspection) showed that's only partly so:

- **Each product has its own Supabase project** (sidekick, echo, redflag, rekkn,
  unihodl, dorea, coyl, elvera, …). EP runs on its own dedicated project
  the current shared production project, region us-west-2.
- **Zero non-EP base tables exist in EP's project.** EP does not share table data
  with any other product. The data layer is already isolated.
- The only co-mingling was **~22 orphaned functions** from other products
  (`hc_*` redflag, `rk_*` rekkn, plus `submit_claim` / `merchant_*` /
  `*verified_number*` / `accept_invitation*` helpers), created here from
  copied/shared migrations. They reference tables that **do not exist** in this
  project → already non-functional, and they were the bulk of the
  anon-executable `SECURITY DEFINER` advisory surface.

## Decision

**Do not migrate projects. Drop the orphaned dead functions.** (migration 122)

Rationale: a cross-project data migration carries real downtime/dual-write/cutover
risk for **zero isolation benefit** — EP already has its own project with no
shared tables. Dropping the orphaned functions removes the only real co-mingling
and shrinks the attack surface. Safe because: no EP code calls them, no EP
triggers use them, they reference non-existent tables, and other products run
their own project copies.

## Residual hardening (tracked, not blocking)

- A handful of generic `SECURITY DEFINER` functions remain anon/authenticated-
  executable (e.g. `create_profile_on_user_insert`, `rls_auto_enable`) — review
  whether each is intentionally callable; lock down those that aren't (pattern:
  migration 112).
- Audit any remaining always-true PUBLIC policies surfaced by the advisor.
- `schema:security` + `schema:reconcile` now guard EP's surface every PR/push/night.

## Contingency: full org/project separation (only if compliance demands it)

If a future requirement forces EP onto a separate Supabase **organization**
(not just project) — e.g. customer-contractual data-residency or hard
blast-radius isolation from the other products' org — execute as scheduled
maintenance, NOT a live chat operation:

1. Provision the new project (target region; record ref + keys).
2. Port schema: apply the full `supabase/migrations/` set to the new project;
   run `schema:reconcile` against it until 0 drift.
3. Recreate RLS + the `schema_gate` role + `gov_schema_contract_introspect`.
4. Data copy: `pg_dump --data-only` per EP table → restore; or logical
   replication for near-zero-downtime; verify row counts + a checksum per table.
5. Re-point env: `NEXT_PUBLIC_SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`,
   `SCHEMA_GATE_DB_URL`, anon key, JWT secret — in Vercel (Sensitive) + GitHub.
6. **Rotate** the old project's service-role + JWT secret after cutover (treat as
   exposed).
7. Cut over behind a maintenance window; keep the old project read-only as
   rollback for N days, then decommission.
8. Re-run `schema:security` against the new project; flip the gate's
   `SCHEMA_GATE_DB_URL` to the new role.
