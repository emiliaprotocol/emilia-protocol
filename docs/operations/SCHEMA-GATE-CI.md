# Schema CI database credential cutover

The live `schema-security` job reads production schema metadata through
`SCHEMA_GATE_DB_URL`. This runbook moves that secret from the existing
`schema_gate` login to a new login, `schema_gate_ci_gha`, whose authority comes
from a group role created by a reviewed migration.

Merging the pull request that adds this file changes no database and no GitHub
setting. Every step is a maintainer action; CI never applies the migration,
creates the login or edits the secret.

Status in the deployed environment: steps 2, 7, 9 and 10 are complete. The
migration-history ledger records step 2 by listing `20260926035734` in
`remote_versions`. The steps below remain the procedure for any other
environment.

## What the role can and cannot do

Migration `20260926035734_schema_gate_ci_role.sql` creates the NOLOGIN group
`schema_gate_ci` and grants it exactly three things: `USAGE` on schema
`public`, and `EXECUTE` on `public.gov_schema_contract_introspect()` and
`public.gov_schema_reconcile_introspect()`. Both functions are
`SECURITY DEFINER` and return catalog metadata only: table, column, policy,
function, index and grant definitions, plus assertion tokens computed from the
system catalogs, never table rows.

The migration creates no login and sets no password. It refuses, with a
`schema_gate_ci refused: ...` reason, when a role of that name already exists
and can log in, holds an elevated attribute, belongs to another role, or owns
or has been granted anything beyond those three grants. A repeated run makes
the same checks.

`tests/schema-gate-ci-role-postgres.test.ts` provisions the login exactly as
step 3 does, connects as it, and proves that it can run the query CI runs while
every one of these fails with `permission denied`: reading, inserting,
updating, deleting or truncating an application table, using a sequence,
creating a table, view, function or schema, altering or dropping an existing
table, granting privileges, creating roles or databases, `SET ROLE` or
`SET SESSION AUTHORIZATION` to any role outside its group, changing its own
role attributes, and calling the functions the introspection functions call
internally.

PostgreSQL has no per-role deny. A member login also holds everything granted
to `PUBLIC`:

- `EXECUTE` on every function whose `EXECUTE` was never revoked from `PUBLIC`.
  A `SECURITY DEFINER` function runs with its owner's rights, so one that is
  still executable by `PUBLIC` can hand this login application rows or change
  them. The test proves this with a deliberately exposed function and proves
  that the step 4 audit lists it.
- `CONNECT` and `TEMPORARY` on the database, PostgreSQL's defaults. Temporary
  tables are private to the session and give no access to application rows.

The two explicit grants are therefore not an effective two-function allowlist
until the step 4 audit comes back clean.

## Cutover, in order

### 1. Merge (maintainer)

Merge the pull request. This lands the migration file and its ledger entry in
`supabase/migration-history.v1.json`; nothing is applied.

### 2. Apply the migration (maintainer, database administrator connection)

Apply `20260926035734` with the procedure used for the versions in
`deployment_sequence` of `supabase/migration-history.v1.json`:
`supabase db push --include-all` applies every version the target journal
lacks, in version order. In that order it comes after `20260925010000` and
before `20260926120000` and `20260926120100`; it is not the last pending
version. Journaling it ahead of an earlier pending version makes that version
retroactive: the ledger must then list it in `retroactive_pending_versions`
with `requires_include_all` true, because the ledger check refuses a
forward-pending version that precedes `remote_head`.

If the tool you apply it with journals its own timestamp, change that row's
`version` in `supabase_migrations.schema_migrations` to `20260926035734` so the
journal matches the repository file.

If it raises `schema_gate_ci refused: ...`, stop. A role with that name
already exists with other authority and must be investigated, not repurposed.
After applying, move the applied versions from the pending lists to
`remote_versions` in a follow-up pull request so `npm run
check:migration-history` stays true.

### 3. Create the login, without a password yet (maintainer, administrator connection)

```sql
-- runbook: provision login
CREATE ROLE schema_gate_ci_gha LOGIN INHERIT
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT schema_gate_ci TO schema_gate_ci_gha;
```

Without a password the login cannot authenticate, so the audit in step 4 runs
before any credential exists.

### 4. Audit effective authority (maintainer, administrator connection)

Run each query as the administrator. Each one names its pass condition. Any
failure blocks the cutover until it is fixed by a reviewed migration, applied
as in step 2; do not revoke by hand in production, because that drifts from
the migration journal.

```sql
-- runbook: audit role attributes
-- Pass: schema_gate_ci has every column false; schema_gate_ci_gha has
-- rolcanlogin and rolinherit true and every other column false.
SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb,
       rolcreaterole, rolreplication, rolbypassrls
FROM pg_catalog.pg_roles
WHERE rolname IN ('schema_gate_ci', 'schema_gate_ci_gha')
ORDER BY rolname;
```

```sql
-- runbook: audit reachable roles
-- Pass: exactly one row, schema_gate_ci.
SELECT role.rolname
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'schema_gate_ci_gha'
  AND pg_catalog.pg_has_role('schema_gate_ci_gha', role.oid, 'MEMBER')
ORDER BY role.rolname;
```

```sql
-- runbook: audit database privileges
-- Pass: can_create is false. can_connect and can_temporary are PostgreSQL's
-- defaults for PUBLIC.
SELECT pg_catalog.has_database_privilege('schema_gate_ci_gha',
         pg_catalog.current_database(), 'CREATE') AS can_create,
       pg_catalog.has_database_privilege('schema_gate_ci_gha',
         pg_catalog.current_database(), 'CONNECT') AS can_connect,
       pg_catalog.has_database_privilege('schema_gate_ci_gha',
         pg_catalog.current_database(), 'TEMPORARY') AS can_temporary;
```

```sql
-- runbook: audit schemas
-- Pass: can_create is false on every row. audit functions reviews the
-- functions in every schema listed here.
SELECT namespace.nspname,
       pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid,
         'USAGE') AS can_use,
       pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid,
         'CREATE') AS can_create
FROM pg_catalog.pg_namespace AS namespace
WHERE namespace.nspname NOT LIKE 'pg\_%'
  AND namespace.nspname <> 'information_schema'
  AND (pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid, 'USAGE')
    OR pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid, 'CREATE'))
ORDER BY namespace.nspname;
```

```sql
-- runbook: audit relations
-- Pass: no rows. Covers tables, views, materialized views, foreign tables,
-- sequences, and column-level grants, in every schema the login can use.
SELECT relation.oid::regclass::text AS relation, privilege.name AS privilege
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS privilege(name)
WHERE namespace.nspname NOT LIKE 'pg\_%'
  AND namespace.nspname <> 'information_schema'
  AND pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid, 'USAGE')
  AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND (
    pg_catalog.has_table_privilege('schema_gate_ci_gha', relation.oid, privilege.name)
    OR (privilege.name IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
      AND pg_catalog.has_any_column_privilege('schema_gate_ci_gha',
        relation.oid, privilege.name))
  )
UNION ALL
SELECT relation.oid::regclass::text, privilege.name
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = relation.relnamespace
CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS privilege(name)
WHERE namespace.nspname NOT LIKE 'pg\_%'
  AND namespace.nspname <> 'information_schema'
  AND pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid, 'USAGE')
  AND relation.relkind = 'S'
  AND pg_catalog.has_sequence_privilege('schema_gate_ci_gha', relation.oid,
        privilege.name)
ORDER BY 1, 2;
```

```sql
-- runbook: audit functions
-- Pass: the only security_definer rows are gov_schema_contract_introspect and
-- gov_schema_reconcile_introspect, both with via_public false. Every other
-- security_definer row must have EXECUTE revoked from PUBLIC and granted to
-- its real callers, unless review shows it cannot read or change application
-- data (trigger and event trigger functions cannot be called directly). Invoker-rights rows run
-- with this login's own privileges, which audit relations bounds; still review
-- any that perform network or file I/O.
SELECT namespace.nspname,
       procedure.proname,
       pg_catalog.pg_get_function_identity_arguments(procedure.oid) AS arguments,
       procedure.prosecdef AS security_definer,
       procedure.prorettype IN ('pg_catalog.trigger'::regtype,
         'pg_catalog.event_trigger'::regtype) AS trigger_function,
       (procedure.proacl IS NULL OR EXISTS (
         SELECT 1 FROM pg_catalog.aclexplode(procedure.proacl) AS acl
         WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       )) AS via_public
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname NOT LIKE 'pg\_%'
  AND namespace.nspname <> 'information_schema'
  AND pg_catalog.has_schema_privilege('schema_gate_ci_gha', namespace.oid, 'USAGE')
  AND pg_catalog.has_function_privilege('schema_gate_ci_gha', procedure.oid, 'EXECUTE')
ORDER BY procedure.prosecdef DESC, namespace.nspname, procedure.proname, arguments;
```

`pg_catalog` functions are excluded: they are PostgreSQL's own, and the
server restricts the dangerous ones to superusers or predefined roles, which
audit reachable roles already rules out.

### 5. Set the password (maintainer)

In an administrator `psql` session run `\password schema_gate_ci_gha`. psql
prompts without echoing and sends only a SCRAM verifier. A password generated
by the password manager is fine. Never put it in a migration, a repository
file, a command line, shell history or a CI log. A migration is worse than it
looks: its statements are stored verbatim in
`supabase_migrations.schema_migrations`, readable by every administrator
connection for as long as the row exists.

### 6. Prove the new credential locally (maintainer, workstation)

Build the Session pooler URL with username `schema_gate_ci_gha.<project-ref>`.
From a checkout of `main`, run the exact code CI runs, reading the URL without
echoing it:

```bash
read -rs SCHEMA_GATE_DB_URL && export SCHEMA_GATE_DB_URL
npm run schema:security && npm run schema:reconcile
unset SCHEMA_GATE_DB_URL
```

Both must pass. Then connect with `psql` as the new login and confirm that
`SELECT 1 FROM public.audit_events LIMIT 1;` fails with `permission denied`.

### 7. Switch the GitHub secret (maintainer, repository settings)

In Settings, Environments, `schema-gate`: set Deployment branches to `main`
only if it is not already, then replace the environment secret
`SCHEMA_GATE_DB_URL` with the new URL.

### 8. Prove it in CI (maintainer)

In Actions, run `schema-security` on `main` with Run workflow. In the
`live-schema-contract` job, the guard step must print that the credential is
present, and both the `schema:security` and `schema:reconcile` steps must run
and pass; `emilia-production-schema-contract-v2` must pass. A green
`candidate-reconciliation` check does not show that the live check ran. If
this fails, put the old URL back in the environment secret; the old login
still works until step 10.

### 9. Remove the repository-level copy (maintainer, repository settings)

In Settings, Secrets and variables, Actions, delete any repository secret
named `SCHEMA_GATE_DB_URL`. Merge-queue runs read the workflow file from the
candidate, so a repository-level copy is readable by candidate code.

### 10. Retire the old login (maintainer, administrator connection)

Only after step 8 passed and nothing else is confirmed to use it:

```sql
ALTER ROLE schema_gate NOLOGIN;
```

Do not drop `schema_gate`. Existing migrations grant and revoke on it by name
and the open-exposure security assertions reference it, so dropping it breaks
migration replay and the live assertions.

## Rotating the login's password

Run steps 5 to 8 again: set a new password with `\password
schema_gate_ci_gha`, prove it locally, replace the environment secret, and run
`schema-security` on `main`. The old password stops working the moment step 5
completes, so do steps 6 to 8 promptly; a nightly or push run in between
exits with the authentication error rather than skipping. If a password was ever written
into a migration, also replace that journal row's `statements` with a comment
saying the login was provisioned out of band.
