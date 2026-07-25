-- Revoke table-level write grants from anon/authenticated on service_role-only
-- secret-bearing infra tables. Column-level revokes (mig 127) closed the SELECT
-- disclosure vector; these tables' write grants are TABLE-level (Supabase
-- bootstrap default), so column REVOKEs left an inherited UPDATE. All four are
-- written exclusively via service_role (auth RPC, cloud tenant auth, SSO mgmt,
-- webhook delivery); no anon/authenticated write path exists. webhook_endpoints
-- and sso_connections are not in the noAnonWrite RLS contract, so a table-level
-- anon write grant on a webhook URL/secret or OIDC client secret is a real
-- integrity vector — close it. service_role/postgres retain all privileges.
REVOKE INSERT, UPDATE, DELETE ON public.api_keys FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.tenant_api_keys FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.sso_connections FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.webhook_endpoints FROM anon, authenticated;;
