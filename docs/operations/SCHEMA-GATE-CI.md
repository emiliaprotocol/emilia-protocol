# Schema CI database credential cutover

The `schema_gate_ci_role` migration creates a `schema_gate_ci` NOLOGIN group
with public-schema `USAGE` and two explicit `EXECUTE` grants:
`gov_schema_contract_introspect()` and `gov_schema_reconcile_introspect()`.
It creates no login and sets no password. The CI login is provisioned separately.

PostgreSQL also grants some function access through `PUBLIC`. A member login
inherits those grants, including on functions outside this migration. Before
activating the new credential, audit every effectively callable function,
especially `SECURITY DEFINER` functions, for indirect access to application
rows. The two explicit grants alone do not establish an effective two-function
allowlist. Keep the old CI credential in place until this audit and the new
connection test pass.

Provision the operational login through the approved database administration
connection after the migration is applied:

```sql
CREATE ROLE schema_gate_ci_gha LOGIN INHERIT
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT schema_gate_ci TO schema_gate_ci_gha;
```

Set its password interactively with psql's `\password schema_gate_ci_gha`,
or through the approved secret manager. Never put the password in a migration,
repository file, terminal command, or CI log. Use the Session pooler username
`schema_gate_ci_gha.<project-ref>` in its connection URL.

From an administrator connection, verify the effective permissions before
placing the URL in GitHub:

```sql
SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
       rolreplication, rolbypassrls
FROM pg_catalog.pg_roles
WHERE rolname IN ('schema_gate_ci', 'schema_gate_ci_gha');

SELECT n.nspname, p.proname,
       pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
       p.prosecdef AS security_definer
FROM pg_catalog.pg_proc AS p
JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
WHERE pg_catalog.has_function_privilege('schema_gate_ci_gha', p.oid, 'EXECUTE')
  AND n.nspname = 'public'
ORDER BY p.prosecdef DESC, p.proname, arguments;

SELECT c.oid::regclass AS accessible_relation
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND (
    pg_catalog.has_table_privilege('schema_gate_ci_gha', c.oid, 'SELECT')
    OR pg_catalog.has_table_privilege('schema_gate_ci_gha', c.oid, 'INSERT')
    OR pg_catalog.has_table_privilege('schema_gate_ci_gha', c.oid, 'UPDATE')
    OR pg_catalog.has_table_privilege('schema_gate_ci_gha', c.oid, 'DELETE')
  );
```

The relation query must return no application relation. Review the full
function list; any callable function that can expose or mutate application data
must be remediated before cutover. Then connect through the Session pooler as
the new login and verify both introspection calls succeed.

Set `SCHEMA_GATE_DB_URL` as an environment secret in GitHub's `schema-gate`
environment, restricted to `main`. Run the trusted `schema-security` workflow
on `main` and confirm both schema truth checks pass. Remove any repository-level
copy of `SCHEMA_GATE_DB_URL`, then disable the old CI login or revoke its old
credential after confirming it has no other consumer. Do not treat a green
candidate reconciliation check as proof that the live database check ran.
