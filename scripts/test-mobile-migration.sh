#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${MOBILE_TEST_DATABASE_URL:?Set MOBILE_TEST_DATABASE_URL to a disposable PostgreSQL database}"

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
do $$ begin create role anon; exception when duplicate_object then null; end $$;
do $$ begin create role authenticated; exception when duplicate_object then null; end $$;
do $$ begin create role service_role; exception when duplicate_object then null; end $$;
create table if not exists entities (entity_id text primary key);
SQL

psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f supabase/migrations/20260715180000_mobile_production_platform.sql
psql "$MOBILE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f tests/mobile-production-migration.sql
