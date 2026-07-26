-- PART 1: service_role-only RLS on four security tables created without it.
ALTER TABLE saml_consumed_assertions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON saml_consumed_assertions;
CREATE POLICY "service_role_all" ON saml_consumed_assertions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

ALTER TABLE revoked_commit_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON revoked_commit_keys;
CREATE POLICY "service_role_all" ON revoked_commit_keys
  FOR ALL TO service_role USING (true) WITH CHECK (true);

ALTER TABLE revoked_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON revoked_sessions;
CREATE POLICY "service_role_all" ON revoked_sessions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

ALTER TABLE session_cutoffs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "service_role_all" ON session_cutoffs;
CREATE POLICY "service_role_all" ON session_cutoffs
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- PART 2: scim_provisioning_tokens secret sweep (127/128 continuation)
REVOKE SELECT, INSERT, UPDATE (token_hash)
  ON public.scim_provisioning_tokens FROM anon, authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.scim_provisioning_tokens FROM anon, authenticated;;
