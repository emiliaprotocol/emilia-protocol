-- SPDX-License-Identifier: Apache-2.0
-- Dedicated, credential-free group role for schema CI. The operational login
-- is provisioned outside migrations (docs/operations/SCHEMA-GATE-CI.md); no
-- password belongs here.
--
-- Explicit authority: USAGE on schema public and EXECUTE on the two
-- metadata-only introspection functions. PostgreSQL has no per-role deny, so
-- every member also holds whatever is granted to PUBLIC. The runbook's
-- pre-cutover audit bounds that inherited authority; this migration cannot.

DO $schema_gate_ci_role$
DECLARE
  gate_role_oid oid;
  contract_oid oid := 'public.gov_schema_contract_introspect()'::regprocedure;
  reconcile_oid oid := 'public.gov_schema_reconcile_introspect()'::regprocedure;
BEGIN
  SELECT oid INTO gate_role_oid
  FROM pg_catalog.pg_roles
  WHERE rolname = 'schema_gate_ci';

  IF gate_role_oid IS NULL THEN
    CREATE ROLE schema_gate_ci NOLOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    SELECT oid INTO gate_role_oid
    FROM pg_catalog.pg_roles
    WHERE rolname = 'schema_gate_ci';
  END IF;

  -- A preexisting role with broader authority is a collision, not a role to
  -- silently repurpose, and a repeated run refuses if the role has drifted.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE oid = gate_role_oid
      AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
           OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'schema_gate_ci refused: the role can log in or holds an elevated attribute';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members
    WHERE member = gate_role_oid
  ) THEN
    RAISE EXCEPTION 'schema_gate_ci refused: the role is a member of another role';
  END IF;

  -- pg_shdepend records every ownership, grant (including column grants),
  -- default privilege and policy that names a role, in every database and on
  -- shared objects. The only dependencies allowed are the grants below.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_shdepend AS dependency
    WHERE dependency.refclassid = 'pg_catalog.pg_authid'::regclass
      AND dependency.refobjid = gate_role_oid
      AND NOT (
        dependency.deptype = 'a'
        AND dependency.objsubid = 0
        AND dependency.dbid = (
          SELECT oid FROM pg_catalog.pg_database
          WHERE datname = pg_catalog.current_database()
        )
        AND (
          (dependency.classid = 'pg_catalog.pg_namespace'::regclass
            AND dependency.objid = 'public'::regnamespace)
          OR (dependency.classid = 'pg_catalog.pg_proc'::regclass
            AND dependency.objid IN (contract_oid, reconcile_oid))
        )
      )
  ) THEN
    RAISE EXCEPTION 'schema_gate_ci refused: the role owns an object or holds a grant, default privilege or policy outside its schema-introspection contract';
  END IF;

  -- On the allowed objects, only the exact privilege, never with grant option.
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace AS namespace,
      LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
    WHERE namespace.nspname = 'public'
      AND acl.grantee = gate_role_oid
      AND (acl.privilege_type <> 'USAGE' OR acl.is_grantable)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure,
      LATERAL pg_catalog.aclexplode(procedure.proacl) AS acl
    WHERE procedure.oid IN (contract_oid, reconcile_oid)
      AND acl.grantee = gate_role_oid
      AND (acl.privilege_type <> 'EXECUTE' OR acl.is_grantable)
  ) THEN
    RAISE EXCEPTION 'schema_gate_ci refused: the role holds more than USAGE on schema public or EXECUTE on the introspection functions';
  END IF;
END
$schema_gate_ci_role$;

GRANT USAGE ON SCHEMA public TO schema_gate_ci;
GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO schema_gate_ci;
GRANT EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect() TO schema_gate_ci;
