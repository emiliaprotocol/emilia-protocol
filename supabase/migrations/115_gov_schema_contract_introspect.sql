-- 115_gov_schema_contract_introspect.sql
--
-- Executable schema contract — the live counterpart to the static gov:check.
-- Returns a JSONB snapshot of the public schema's actual shape (tables, columns,
-- RLS flags, policies with roles+expressions, functions with ACLs, indexes) so a
-- checker can assert "the control object EXISTS with the expected shape in prod",
-- not merely "a migration was journaled". Motivated by drift where migrations
-- were journaled-as-applied but their objects never existed (incl. a missing
-- authorities table and anon-scoped policies named 'service role only').
--
-- Read-only. Locked to service_role (no anon/authenticated/PUBLIC execute),
-- consistent with the migration 112/113 hardening.

CREATE OR REPLACE FUNCTION public.gov_schema_contract_introspect()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path TO 'public', 'pg_catalog'
AS $$
  SELECT jsonb_build_object(
    'tables', (
      SELECT coalesce(jsonb_agg(t.table_name ORDER BY t.table_name), '[]'::jsonb)
      FROM information_schema.tables t
      WHERE t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
    ),
    'columns', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', table_name, 'c', column_name, 'type', data_type, 'nullable', is_nullable
      ) ORDER BY table_name, column_name), '[]'::jsonb)
      FROM information_schema.columns WHERE table_schema = 'public'
    ),
    'rls', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname, 'enabled', c.relrowsecurity
      ) ORDER BY c.relname), '[]'::jsonb)
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    ),
    'policies', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'name', p.polname,
        'cmd', CASE p.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' END,
        'roles', (SELECT coalesce(jsonb_agg(CASE WHEN r.oid = 0 THEN 'PUBLIC' ELSE r.rolname END), '["PUBLIC"]'::jsonb)
                  FROM unnest(p.polroles) ro(oid) LEFT JOIN pg_roles r ON r.oid = ro.oid),
        'using', pg_get_expr(p.polqual, p.polrelid),
        'check', pg_get_expr(p.polwithcheck, p.polrelid)
      )), '[]'::jsonb)
      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
    ),
    'functions', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        'name', p.proname,
        'args', pg_get_function_identity_arguments(p.oid),
        'secdef', p.prosecdef,
        'acl', coalesce(p.proacl::text, '')
      )), '[]'::jsonb)
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
    ),
    'indexes', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', tablename, 'name', indexname
      ) ORDER BY indexname), '[]'::jsonb)
      FROM pg_indexes WHERE schemaname = 'public'
    )
  );
$$;

REVOKE EXECUTE ON FUNCTION public.gov_schema_contract_introspect() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO service_role;
