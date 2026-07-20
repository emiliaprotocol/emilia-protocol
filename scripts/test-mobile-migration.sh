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
SQL

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f supabase/migrations/20260715180000_mobile_production_platform.sql \
  -f supabase/migrations/20260717072000_mobile_sessions_device_key_index.sql \
  -f supabase/migrations/20260720181619_mobile_action_continuity.sql \
  -f supabase/migrations/20260720182147_mobile_pgcrypto_schema_pin.sql \
  -f supabase/migrations/20260720182519_mobile_action_advisor_hardening.sql \
  -f supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql
PGOPTIONS='-c search_path=public,extensions,pg_temp' \
psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f tests/mobile-production-migration.sql
PGOPTIONS='-c search_path=public,extensions,pg_temp' \
psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f tests/mobile-action-continuity-migration.sql
