-- SPDX-License-Identifier: Apache-2.0
-- Drop three SECURITY DEFINER functions that no EMILIA migration creates.
--
-- public.complete_verified_activation(text,text,text,timestamptz),
-- public.complete_verified_activation(uuid,uuid,text,text), and
-- public.create_profile_on_user_insert() reached the EMILIA production project
-- from other products' migrations (the rk_* and hc_* schemas described in
-- docs/DB-ISOLATION-PLAN.md). Their tables and helper functions do not exist in
-- EMILIA, no trigger or other object depends on them, and all three carry the
-- default EXECUTE grants to PUBLIC, anon, and authenticated. The two
-- complete_verified_activation overloads fail at runtime on their first table
-- reference; create_profile_on_user_insert is a trigger function attached to
-- no trigger. Dropping them removes dead definer surface.
--
-- public.rls_auto_enable() is intentionally kept. It backs the ensure_rls
-- ddl_command_end event trigger that enables row-level security on new public
-- tables, and PostgreSQL rejects any direct call to an event-trigger function.
--
-- IF EXISTS keeps this a no-op where the functions never existed. The drop
-- refuses to run where any table they write exists, because there they are not
-- orphans.
DO $foreign_activation_preconditions$
BEGIN
  IF pg_catalog.to_regclass('public.rk_users') IS NOT NULL
    OR pg_catalog.to_regclass('public.rk_email_verifications') IS NOT NULL
    OR pg_catalog.to_regclass('public.rk_sessions') IS NOT NULL
    OR pg_catalog.to_regclass('public.hc_profiles') IS NOT NULL
    OR pg_catalog.to_regclass('public.hc_users') IS NOT NULL
    OR pg_catalog.to_regclass('public.hc_audit_log') IS NOT NULL
  THEN
    RAISE EXCEPTION
      'rk_*/hc_* tables exist; complete_verified_activation and create_profile_on_user_insert are not orphans here'
      USING ERRCODE = '55000';
  END IF;
END
$foreign_activation_preconditions$;

DROP FUNCTION IF EXISTS public.complete_verified_activation(TEXT, TEXT, TEXT, TIMESTAMPTZ);
DROP FUNCTION IF EXISTS public.complete_verified_activation(UUID, UUID, TEXT, TEXT);
DROP FUNCTION IF EXISTS public.create_profile_on_user_insert();
