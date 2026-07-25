# Migration history reconciliation archive

These files are historical evidence, not executable migrations.

On 2026-07-25, the production migration journal was reconciled with the public
repository. Timestamp aliases, placeholders, and old local-only copies were
moved here so Supabase tooling sees exactly one executable file per journaled
public version. `SHA256SUMS` pins every archived SQL file.

The executable ledger is `supabase/migration-history.v1.json`. It records:

- the production-journal versions;
- the exact SHA-256 of every public executable migration;
- the migrations still pending production application; and
- journaled versions intentionally retained only in private deployment history.

Version `20260723192504` is intentionally absent from this public repository.
The recovered historical file contained deployment credentials, so it is kept
in the ignored private deployment-history directory of the private company
repository. No public placeholder represents it. Migration
`20260725174433_disable_legacy_consequence_canary_logins.sql` disables those
legacy login roles, clears their passwords, and revokes their consequence-store
memberships.

Run `npm run check:migration-history` before changing migration history. Never
restore an archived alias to `supabase/migrations`, edit a journaled migration,
or use migration-journal repair to hide a filesystem mismatch.

The security invariants that were still required but had no journaled
equivalent are reintroduced idempotently by
`20260725180000_reconcile_unjournaled_security_invariants.sql`. The archive is
not a runtime dependency.
