-- SPDX-License-Identifier: Apache-2.0
-- Dedicated, credential-free group role for schema CI. Provision a separate
-- login and grant it membership outside migrations; no password belongs here.

DO $schema_gate_ci_role$
DECLARE
  gate_role_oid oid;
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
  -- silently repurpose. This also makes a repeated migration fail closed if
  -- its privileges drift after the first application.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE oid = gate_role_oid
      AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
           OR rolreplication OR rolbypassrls)
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members
    WHERE member = gate_role_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_class AS relation
    WHERE relation.relowner = gate_role_oid
       OR EXISTS (
         SELECT 1 FROM pg_catalog.aclexplode(relation.relacl) AS acl
         WHERE acl.grantee = gate_role_oid
       )
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_default_acl AS defaults,
      LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS acl
    WHERE acl.grantee = gate_role_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspowner = gate_role_oid
       OR EXISTS (
         SELECT 1 FROM pg_catalog.aclexplode(namespace.nspacl) AS acl
         WHERE acl.grantee = gate_role_oid
           AND (namespace.nspname <> 'public'
             OR acl.privilege_type <> 'USAGE' OR acl.is_grantable)
       )
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS proc
    WHERE proc.proowner = gate_role_oid
       OR EXISTS (
         SELECT 1 FROM pg_catalog.aclexplode(proc.proacl) AS acl
         WHERE acl.grantee = gate_role_oid
           AND (proc.oid NOT IN (
               'public.gov_schema_contract_introspect()'::regprocedure,
               'public.gov_schema_reconcile_introspect()'::regprocedure
             ) OR acl.privilege_type <> 'EXECUTE' OR acl.is_grantable)
       )
  ) THEN
    RAISE EXCEPTION 'schema_gate_ci already has authority outside its schema-introspection contract';
  END IF;
END
$schema_gate_ci_role$;

GRANT USAGE ON SCHEMA public TO schema_gate_ci;
GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO schema_gate_ci;
GRANT EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect() TO schema_gate_ci;
