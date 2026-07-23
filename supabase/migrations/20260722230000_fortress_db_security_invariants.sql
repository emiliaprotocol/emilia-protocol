-- SPDX-License-Identifier: Apache-2.0
-- Migration version: 20260722230000
--
-- Forward-only Fortress reassertion for the AEB and remedy durable stores.
-- No runtime role, including Supabase service_role, receives direct table
-- authority. Tenant-bound, no-bypass executor/recovery roles reach only the
-- narrow SECURITY DEFINER functions established by the preceding migrations.

GRANT ep_aeb_store_owner, ep_remedy_store_owner TO CURRENT_USER;

ALTER SCHEMA ep_aeb_private OWNER TO ep_aeb_store_owner;
ALTER TABLE ep_aeb_private.tenant_principals OWNER TO ep_aeb_store_owner;
ALTER TABLE public.ep_aeb_consumption_operations OWNER TO ep_aeb_store_owner;
ALTER TABLE public.ep_aeb_consumption_replay_fences OWNER TO ep_aeb_store_owner;
ALTER SCHEMA ep_remedy_private OWNER TO ep_remedy_store_owner;
ALTER TABLE ep_remedy_private.tenant_principals OWNER TO ep_remedy_store_owner;
ALTER TABLE public.ep_remedy_case_sets OWNER TO ep_remedy_store_owner;
ALTER TABLE public.ep_remedy_case_set_events OWNER TO ep_remedy_store_owner;

ALTER TABLE public.ep_aeb_consumption_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_replay_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_remedy_case_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_remedy_case_set_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ep_remedy_case_sets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_remedy_case_set_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ep_aeb_consumption_replay_fences FORCE ROW LEVEL SECURITY;
ALTER TABLE ep_aeb_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_aeb_private.tenant_principals FORCE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_private.tenant_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ep_remedy_private.tenant_principals FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.ep_aeb_consumption_operations
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON TABLE public.ep_aeb_consumption_replay_fences
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON TABLE public.ep_remedy_case_sets
  FROM PUBLIC, anon, authenticated, service_role, ep_remedy_executor;
REVOKE ALL ON TABLE public.ep_remedy_case_set_events
  FROM PUBLIC, anon, authenticated, service_role, ep_remedy_executor;
REVOKE ALL ON TABLE ep_aeb_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, ep_aeb_executor, ep_aeb_recovery;
REVOKE ALL ON TABLE ep_remedy_private.tenant_principals
  FROM PUBLIC, anon, authenticated, service_role, ep_remedy_executor;

REVOKE ALL ON SCHEMA ep_aeb_private FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON SCHEMA ep_remedy_private FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_aeb_private
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ep_remedy_private
  FROM PUBLIC, anon, authenticated, service_role;

DROP POLICY IF EXISTS ep_aeb_principals_owner_only
  ON ep_aeb_private.tenant_principals;
CREATE POLICY ep_aeb_principals_owner_only
  ON ep_aeb_private.tenant_principals
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS ep_aeb_operations_owner_only
  ON public.ep_aeb_consumption_operations;
CREATE POLICY ep_aeb_operations_owner_only
  ON public.ep_aeb_consumption_operations
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS ep_aeb_replay_owner_only
  ON public.ep_aeb_consumption_replay_fences;
CREATE POLICY ep_aeb_replay_owner_only
  ON public.ep_aeb_consumption_replay_fences
  TO ep_aeb_store_owner USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS ep_remedy_principals_owner_only
  ON ep_remedy_private.tenant_principals;
CREATE POLICY ep_remedy_principals_owner_only
  ON ep_remedy_private.tenant_principals
  TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS ep_remedy_case_sets_tenant_policy
  ON public.ep_remedy_case_sets;
DROP POLICY IF EXISTS ep_remedy_case_sets_owner_only
  ON public.ep_remedy_case_sets;
CREATE POLICY ep_remedy_case_sets_owner_only
  ON public.ep_remedy_case_sets
  TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);

DROP POLICY IF EXISTS ep_remedy_case_set_events_tenant_policy
  ON public.ep_remedy_case_set_events;
DROP POLICY IF EXISTS ep_remedy_case_set_events_owner_only
  ON public.ep_remedy_case_set_events;
CREATE POLICY ep_remedy_case_set_events_owner_only
  ON public.ep_remedy_case_set_events
  TO ep_remedy_store_owner USING (TRUE) WITH CHECK (TRUE);

ALTER FUNCTION ep_aeb_private.assert_tenant_principal(TEXT, BOOLEAN)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[])
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  OWNER TO ep_aeb_store_owner;
ALTER FUNCTION ep_remedy_private.assert_tenant_principal(TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.create_case_set(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.get_case_set(TEXT, TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.get_case_set_for_update(TEXT, TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.compare_and_swap_case_set(TEXT, TEXT, BIGINT, TEXT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT)
  OWNER TO ep_remedy_store_owner;
ALTER FUNCTION ep_remedy_private.append_case_set_event(TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  OWNER TO ep_remedy_store_owner;

GRANT USAGE ON SCHEMA ep_aeb_private TO ep_aeb_executor, ep_aeb_recovery;
GRANT EXECUTE ON FUNCTION ep_aeb_private.reserve_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.reserve_replay_keys(TEXT, TEXT, TEXT, TEXT[]),
  ep_aeb_private.commit_operation(TEXT, TEXT, TEXT, TEXT),
  ep_aeb_private.release_operation(TEXT, TEXT, TEXT, TEXT)
  TO ep_aeb_executor;
GRANT EXECUTE ON FUNCTION ep_aeb_private.claim_operation(TEXT, TEXT, TEXT, TEXT)
  TO ep_aeb_recovery;
GRANT USAGE ON SCHEMA ep_remedy_private TO ep_remedy_executor;
GRANT EXECUTE ON FUNCTION ep_remedy_private.assert_tenant_principal(TEXT),
  ep_remedy_private.create_case_set(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ),
  ep_remedy_private.get_case_set(TEXT, TEXT),
  ep_remedy_private.get_case_set_for_update(TEXT, TEXT),
  ep_remedy_private.compare_and_swap_case_set(TEXT, TEXT, BIGINT, TEXT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ, TEXT, TEXT),
  ep_remedy_private.append_case_set_event(TEXT, TEXT, BIGINT, BIGINT, TEXT, TEXT, TEXT, TIMESTAMPTZ)
  TO ep_remedy_executor;

REVOKE ep_aeb_store_owner, ep_remedy_store_owner FROM CURRENT_USER;
