# RLS and Tenancy

Government mode assumes fail-closed tenant binding.

Rules:

- derive organization from the authenticated entity
- treat request-body `organization_id` as a cross-check only
- reject body/auth organization mismatch
- reject unbound entities on v1 write paths
- public/sandbox-created entities must be org-bound when created
- service-role access must be wrapped by write guards on trust-bearing tables

Relevant controls:

- `lib/tenant-binding.js`
- `lib/write-guard.js`
- `supabase/migrations/101_entity_organization_binding.sql`
- `supabase/migrations/076_rls_policies_all_tables.sql`
- `supabase/migrations/088_apply_076_rls_policies_idempotent.sql`

The static readiness check verifies the core tenant-bound v1 surfaces include `requireBound: true`.
