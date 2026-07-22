-- Forward-only repair for the migration journal reconciliation gate.
--
-- gov_schema_contract_introspect() deliberately exposes the public API schema
-- used by the executable DB contract.  Trust Program and Remedy Program state
-- live in private schemas, so comparing every migration-declared object only
-- against that public snapshot creates a false "journal lied" result after a
-- successful deployment.  This metadata-only companion returns qualified
-- names for every non-system table/function without reading application rows.

CREATE OR REPLACE FUNCTION public.gov_schema_reconcile_introspect()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $$
  SELECT jsonb_build_object(
    'tables', (
      SELECT coalesce(jsonb_agg(object_name ORDER BY object_name), '[]'::jsonb)
      FROM (
        SELECT CASE
          WHEN n.nspname = 'public' THEN c.relname
          ELSE n.nspname || '.' || c.relname
        END AS object_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname !~ '^pg_(toast|temp)'
      ) qualified_tables
    ),
    'functions', (
      SELECT coalesce(jsonb_agg(object_name ORDER BY object_name), '[]'::jsonb)
      FROM (
        SELECT DISTINCT CASE
          WHEN n.nspname = 'public' THEN p.proname
          ELSE n.nspname || '.' || p.proname
        END AS object_name
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname !~ '^pg_(toast|temp)'
      ) qualified_functions
    )
  );
$$;

REVOKE EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gov_schema_reconcile_introspect()
  TO service_role, schema_gate;
