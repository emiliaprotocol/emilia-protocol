#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${MOBILE_TEST_DATABASE_URL:?Set MOBILE_TEST_DATABASE_URL to a disposable PostgreSQL database}"

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
do $$ begin create role anon; exception when duplicate_object then null; end $$;
do $$ begin create role authenticated; exception when duplicate_object then null; end $$;
do $$ begin create role service_role; exception when duplicate_object then null; end $$;
create table if not exists entities (entity_id text primary key);
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- The repository-wide canactid transition also updates four non-mobile
-- stores. This disposable mobile harness supplies only the relations and
-- columns the canonical migration needs, rather than importing those stores'
-- unrelated migration chains into the mobile contract.
create table if not exists approval_acquisition_requests (action_caid text);
create schema if not exists trust_program_private;
create table if not exists trust_program_private.trust_roots (root_caid text);
create table if not exists arena_attempts (caid text);

-- Reproduce the production custody boundary instead of letting the disposable
-- superuser mask owner-role failures in a repository-wide migration.
do $$ begin
  create role ep_open_exposure_store_owner nologin nosuperuser
    nocreatedb nocreaterole noreplication nobypassrls;
exception when duplicate_object then null;
end $$;
do $$ begin
  create role ep_canactid_migration_runner nologin nosuperuser
    nocreatedb createrole noreplication nobypassrls;
exception when duplicate_object then null;
end $$;
grant ep_open_exposure_store_owner to ep_canactid_migration_runner
  with admin true, inherit false, set false;
grant ep_open_exposure_store_owner to current_user
  with inherit false, set true;
create schema if not exists open_exposure_private
  authorization ep_open_exposure_store_owner;
set role ep_open_exposure_store_owner;
create table if not exists open_exposure_private.exposures (caid text);
create or replace function open_exposure_private.reserve(p_input jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_input ->> 'caid' !~ '^caid:1:' then
    raise exception 'legacy CAID required by pre-transition fixture';
  end if;
  return p_input;
end
$$;
create or replace function open_exposure_private.begin_invocation(p_input jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_input ->> 'caid' !~ '^caid:1:' then
    raise exception 'legacy CAID required by pre-transition fixture';
  end if;
  return p_input;
end
$$;
reset role;
revoke ep_open_exposure_store_owner from current_user;
SQL

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f supabase/migrations/20260717072053_mobile_production_platform.sql \
  -f supabase/migrations/20260717072216_mobile_sessions_device_key_index.sql \
  -f supabase/migrations/20260720181619_mobile_action_continuity.sql \
  -f supabase/migrations/20260720182147_mobile_pgcrypto_schema_pin.sql \
  -f supabase/migrations/20260720182519_mobile_action_advisor_hardening.sql \
  -f supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
alter table public.mobile_action_groups owner to ep_canactid_migration_runner;
alter table public.mobile_action_revisions owner to ep_canactid_migration_runner;
alter table public.mobile_action_challenges owner to ep_canactid_migration_runner;
alter table public.mobile_action_operations owner to ep_canactid_migration_runner;
alter table public.approval_acquisition_requests owner to ep_canactid_migration_runner;
alter table trust_program_private.trust_roots owner to ep_canactid_migration_runner;
alter table public.arena_attempts owner to ep_canactid_migration_runner;
grant usage, create on schema public, trust_program_private
  to ep_canactid_migration_runner;

do $$
declare
  v_function record;
begin
  for v_function in
    select proc.oid::pg_catalog.regprocedure as signature
    from pg_catalog.pg_proc as proc
    join pg_catalog.pg_namespace as namespace on namespace.oid = proc.pronamespace
    where (
      namespace.nspname = 'public'
      and proc.proname in (
        'create_mobile_demo_action_v2',
        'create_grace_mobile_action_group_v2',
        'supersede_mobile_action',
        'attempt_arena_action'
      )
    ) or (
      namespace.nspname = 'trust_program_private'
      and proc.proname = 'validate_state'
    )
  loop
    execute pg_catalog.format(
      'alter function %s owner to ep_canactid_migration_runner',
      v_function.signature
    );
  end loop;
end
$$;
SQL

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -1 \
  -c 'set role ep_canactid_migration_runner' \
  -f supabase/migrations/20261005090000_canactid_scheme_transition.sql

# Restore the disposable fixture's original runtime owner before exercising
# SECURITY DEFINER behavior. The migration itself has already run under the
# non-superuser owner reproduction above; production ownership never changes.
psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
alter table public.mobile_action_groups owner to current_user;
alter table public.mobile_action_revisions owner to current_user;
alter table public.mobile_action_challenges owner to current_user;
alter table public.mobile_action_operations owner to current_user;
alter table public.approval_acquisition_requests owner to current_user;
alter table trust_program_private.trust_roots owner to current_user;
alter table public.arena_attempts owner to current_user;

do $$
declare
  v_function record;
begin
  for v_function in
    select proc.oid::pg_catalog.regprocedure as signature
    from pg_catalog.pg_proc as proc
    join pg_catalog.pg_namespace as namespace on namespace.oid = proc.pronamespace
    where (
      namespace.nspname = 'public'
      and proc.proname in (
        'create_mobile_demo_action_v2',
        'create_grace_mobile_action_group_v2',
        'supersede_mobile_action',
        'attempt_arena_action'
      )
    ) or (
      namespace.nspname = 'trust_program_private'
      and proc.proname = 'validate_state'
    )
  loop
    execute pg_catalog.format(
      'alter function %s owner to %I',
      v_function.signature,
      current_user
    );
  end loop;
end
$$;
SQL

PGOPTIONS='-c search_path=public,extensions,pg_temp' \
psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f tests/mobile-production-migration.sql
PGOPTIONS='-c search_path=public,extensions,pg_temp' \
psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f tests/mobile-action-continuity-migration.sql

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
do $$
declare
  v_memberships integer;
  v_owner text;
begin
  perform open_exposure_private.reserve(
    jsonb_build_object(
      'caid',
      'canactid:1:example.action.1:jcs-sha256:' || repeat('A', 43)
    )
  );
  perform open_exposure_private.begin_invocation(
    jsonb_build_object(
      'caid',
      'caid:1:example.action.1:jcs-sha256:' || repeat('B', 43)
    )
  );

  select owner_role.rolname
  into v_owner
  from pg_catalog.pg_class as relation
  join pg_catalog.pg_namespace as namespace on namespace.oid = relation.relnamespace
  join pg_catalog.pg_roles as owner_role on owner_role.oid = relation.relowner
  where namespace.nspname = 'open_exposure_private'
    and relation.relname = 'exposures';
  if v_owner is distinct from 'ep_open_exposure_store_owner' then
    raise exception 'open-exposure ownership changed during canactid migration';
  end if;

  select count(*)
  into v_memberships
  from pg_catalog.pg_auth_members as membership
  join pg_catalog.pg_roles as granted_role on granted_role.oid = membership.roleid
  join pg_catalog.pg_roles as member_role on member_role.oid = membership.member
  where granted_role.rolname = 'ep_open_exposure_store_owner'
    and member_role.rolname = 'ep_canactid_migration_runner'
    and (membership.inherit_option or membership.set_option);
  if v_memberships <> 0 then
    raise exception 'temporary open-exposure owner membership was not revoked';
  end if;
end
$$;
SQL
