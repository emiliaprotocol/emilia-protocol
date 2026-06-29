-- 121_introspect_security_definer.sql
--
-- gov_schema_contract_introspect (mig 115) was SECURITY INVOKER. That breaks the
-- least-privilege gate role: information_schema.tables is privilege-filtered, so
-- when the dedicated read-only `schema_gate` role calls it, it sees only tables
-- it has grants on (none) and the contract falsely reports tables missing.
--
-- Flip to SECURITY DEFINER so it returns the FULL public-schema SHAPE regardless
-- of caller grants. Safe: the function only reads catalog METADATA (table/column/
-- policy/function names + ACLs), never row data; search_path is pinned; and
-- EXECUTE stays restricted to service_role + schema_gate (anon/authenticated/
-- PUBLIC remain revoked). schema_gate still cannot read any table rows.

ALTER FUNCTION public.gov_schema_contract_introspect() SECURITY DEFINER;

REVOKE EXECUTE ON FUNCTION public.gov_schema_contract_introspect() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gov_schema_contract_introspect() TO service_role, schema_gate;
