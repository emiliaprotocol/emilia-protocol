-- SPDX-License-Identifier: Apache-2.0
--
-- The schema contract pins public mutation roots by their identity argument
-- types. pg_get_function_identity_arguments() preserves declared argument
-- names on hosted PostgreSQL, while the contract compares the canonical type
-- list. Emit oidvectortypes(proargtypes) so the live snapshot and the contract
-- use the same overload identity representation.

CREATE OR REPLACE FUNCTION public.gov_schema_contract_introspect()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
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
        't', c.relname,
        'enabled', c.relrowsecurity,
        'forced', c.relforcerowsecurity
      ) ORDER BY c.relname), '[]'::jsonb)
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    ),
    'policies', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'name', p.polname,
        'cmd', CASE p.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' END,
        'roles', (SELECT coalesce(jsonb_agg(
                    CASE WHEN ro.oid = 0 THEN 'PUBLIC' ELSE r.rolname END
                  ), '["PUBLIC"]'::jsonb)
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
        'args', oidvectortypes(p.proargtypes),
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
    ),
    'table_grants', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'grantee', CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END,
        'privilege', x.privilege_type,
        'grantable', x.is_grantable
      ) ORDER BY c.relname, x.privilege_type, x.grantee), '[]'::jsonb)
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) x
      LEFT JOIN pg_roles r ON r.oid = x.grantee
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    ),
    'column_grants', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        't', c.relname,
        'c', a.attname,
        'grantee', CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.rolname END,
        'privilege', x.privilege_type,
        'grantable', x.is_grantable
      ) ORDER BY c.relname, a.attname, x.privilege_type, x.grantee), '[]'::jsonb)
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(a.attacl) x
      LEFT JOIN pg_roles r ON r.oid = x.grantee
      WHERE n.nspname = 'public'
        AND c.relkind = 'r'
        AND a.attnum > 0
        AND a.attacl IS NOT NULL
        AND NOT a.attisdropped
    )
  );
$$;

REVOKE EXECUTE ON FUNCTION public.gov_schema_contract_introspect()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect()
  TO service_role, schema_gate;
