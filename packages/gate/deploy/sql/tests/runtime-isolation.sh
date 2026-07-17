#!/usr/bin/env bash
set -euo pipefail

test_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
migration="$(cd "$test_dir/.." && pwd)/001-runtime.sql"
postgres_image="${POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
container="emilia-gate-isolation-$RANDOM-$$"
admin_password='gate-isolation-admin'
database='gate_isolation'
host_port=''

for command in docker psql; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for the live Postgres isolation test" >&2
    exit 127
  fi
done

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --rm \
  --name "$container" \
  --env POSTGRES_PASSWORD="$admin_password" \
  --env POSTGRES_DB="$database" \
  --publish 127.0.0.1::5432 \
  "$postgres_image" >/dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "$container" pg_isready --username postgres --dbname "$database" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  echo 'Postgres test container did not become ready' >&2
  docker logs "$container" >&2 || true
  exit 1
fi

host_port="$(docker port "$container" 5432/tcp | awk -F: 'NR == 1 { print $NF }')"
if [[ -z "$host_port" ]]; then
  echo 'could not determine the Postgres test port' >&2
  exit 1
fi

psql_as() {
  local role="$1"
  local password="$2"
  shift 2
  PGPASSWORD="$password" psql \
    --host=127.0.0.1 \
    --port="$host_port" \
    --username="$role" \
    --dbname="$database" \
    --set=ON_ERROR_STOP=1 \
    --no-psqlrc \
    "$@"
}

psql_as postgres "$admin_password" >/dev/null <<'SQL'
CREATE ROLE gate_migrator
  LOGIN NOSUPERUSER NOCREATEDB CREATEROLE INHERIT NOREPLICATION
  PASSWORD 'gate-isolation-migrator';
ALTER DATABASE gate_isolation OWNER TO gate_migrator;
SQL

psql_as gate_migrator 'gate-isolation-migrator' --file="$migration" >/dev/null
psql_as gate_migrator 'gate-isolation-migrator' --file="$migration" >/dev/null

psql_as gate_migrator 'gate-isolation-migrator' >/dev/null <<'SQL'
CREATE ROLE gate_tenant_a
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
  PASSWORD 'gate-isolation-tenant-a';
CREATE ROLE gate_tenant_b
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
  PASSWORD 'gate-isolation-tenant-b';
GRANT emilia_gate_evidence_runtime TO gate_tenant_a, gate_tenant_b;
SELECT emilia_gate_evidence.grant_runtime_scope(
  'gate_tenant_a', 'tenant-a', 'gate-a', 'stream-a'
);
SELECT emilia_gate_evidence.grant_runtime_scope(
  'gate_tenant_b', 'tenant-b', 'gate-b', 'stream-b'
);
SELECT emilia_gate_evidence.grant_network_witness_scope(
  'gate_tenant_a',
  'tenant-a',
  'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex')
);
SELECT emilia_gate_evidence.grant_network_witness_scope(
  'gate_tenant_a',
  'tenant-a',
  'gate-a',
  decode('7769746e6573733a656467652d3300636170747572653a72616365', 'hex')
);
SELECT emilia_gate_evidence.grant_network_witness_scope(
  'gate_tenant_b',
  'tenant-b',
  'gate-b',
  decode('7769746e6573733a656467652d3200636170747572653a62', 'hex')
);
SQL

append_a="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
WITH canonical AS (
  SELECT '{"prev_hash":"genesis","record_id":"tenant-a-record-0001","seq":0}'::text AS body
), payload AS (
  SELECT
    body,
    body::jsonb || jsonb_build_object(
      'hash', encode(public.digest(convert_to(body, 'UTF8'), 'sha256'), 'hex')
    ) AS record
  FROM canonical
)
SELECT emilia_gate_evidence.append_record(
  'tenant-a', 'gate-a', 'stream-a', NULL, record, body
)
FROM payload;
SQL
)"
if [[ "$append_a" != 't' ]]; then
  echo "tenant A append did not succeed: $append_a" >&2
  exit 1
fi

unauthorized_output="$(mktemp)"
if psql_as gate_tenant_b 'gate-isolation-tenant-b' --quiet >"$unauthorized_output" 2>&1 <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT emilia_gate_evidence.append_record(
  'tenant-a',
  'gate-a',
  'stream-a',
  NULL,
  '{"seq":0,"record_id":"tenant-a-record-0001","prev_hash":"genesis","hash":"0000000000000000000000000000000000000000000000000000000000000000"}'::jsonb,
  '{"prev_hash":"genesis","record_id":"tenant-a-record-0001","seq":0}'
);
SQL
then
  echo 'tenant B unexpectedly appended to tenant A scope' >&2
  rm -f "$unauthorized_output"
  exit 1
fi
if ! grep -Fq 'not authorized for session login gate_tenant_b' "$unauthorized_output"; then
  echo 'cross-tenant append failed for an unexpected reason' >&2
  cat "$unauthorized_output" >&2
  rm -f "$unauthorized_output"
  exit 1
fi
rm -f "$unauthorized_output"

append_b="$(psql_as gate_tenant_b 'gate-isolation-tenant-b' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
WITH canonical AS (
  SELECT '{"prev_hash":"genesis","record_id":"tenant-b-record-0001","seq":0}'::text AS body
), payload AS (
  SELECT
    body,
    body::jsonb || jsonb_build_object(
      'hash', encode(public.digest(convert_to(body, 'UTF8'), 'sha256'), 'hex')
    ) AS record
  FROM canonical
)
SELECT emilia_gate_evidence.append_record(
  'tenant-b', 'gate-b', 'stream-b', NULL, record, body
)
FROM payload;
SQL
)"
if [[ "$append_b" != 't' ]]; then
  echo "tenant B append did not succeed: $append_b" >&2
  exit 1
fi

witness_first="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex'), 7,
  'sha256:1111111111111111111111111111111111111111111111111111111111111111'
);
SQL
)"
witness_replay="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex'), 7,
  'sha256:1111111111111111111111111111111111111111111111111111111111111111'
);
SQL
)"
witness_rollback="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex'), 6,
  'sha256:2222222222222222222222222222222222222222222222222222222222222222'
);
SQL
)"
witness_equivocation="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex'), 7,
  'sha256:2222222222222222222222222222222222222222222222222222222222222222'
);
SQL
)"
witness_advance="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex'), 8,
  'sha256:3333333333333333333333333333333333333333333333333333333333333333'
);
SQL
)"
if [[ "$witness_first" != 'true:' \
      || "$witness_replay" != 'false:statement_replay' \
      || "$witness_rollback" != 'false:sequence_rollback' \
      || "$witness_equivocation" != 'false:sequence_equivocation' \
      || "$witness_advance" != 'false:sequence_equivocation' ]]; then
  echo "network-witness outcomes were unexpected: first=$witness_first replay=$witness_replay rollback=$witness_rollback equivocation=$witness_equivocation advance=$witness_advance" >&2
  exit 1
fi

race_one="$(mktemp)"
race_two="$(mktemp)"
psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align \
  --command="SET ROLE emilia_gate_evidence_runtime; SELECT accepted::text || ':' || coalesce(reason, '') FROM emilia_gate_evidence.advance_network_witness_checkpoint('tenant-a', 'gate-a', decode('7769746e6573733a656467652d3300636170747572653a72616365', 'hex'), 9, 'sha256:6666666666666666666666666666666666666666666666666666666666666666');" \
  >"$race_one" &
race_one_pid=$!
psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align \
  --command="SET ROLE emilia_gate_evidence_runtime; SELECT accepted::text || ':' || coalesce(reason, '') FROM emilia_gate_evidence.advance_network_witness_checkpoint('tenant-a', 'gate-a', decode('7769746e6573733a656467652d3300636170747572653a72616365', 'hex'), 9, 'sha256:7777777777777777777777777777777777777777777777777777777777777777');" \
  >"$race_two" &
race_two_pid=$!
wait "$race_one_pid"
wait "$race_two_pid"
race_outcomes="$(sort "$race_one" "$race_two")"
rm -f "$race_one" "$race_two"
if [[ "$race_outcomes" != $'false:sequence_equivocation\ntrue:' ]]; then
  echo "concurrent witness race was not serialized atomically: $race_outcomes" >&2
  exit 1
fi

race_poisoned="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3300636170747572653a72616365', 'hex'), 10,
  'sha256:8888888888888888888888888888888888888888888888888888888888888888'
);
SQL
)"
if [[ "$race_poisoned" != 'false:sequence_equivocation' ]]; then
  echo "concurrent witness equivocation did not poison the stream: $race_poisoned" >&2
  exit 1
fi

unauthorized_witness_output="$(mktemp)"
if psql_as gate_tenant_b 'gate-isolation-tenant-b' --quiet >"$unauthorized_witness_output" 2>&1 <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT *
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-a', 'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex'), 9,
  'sha256:4444444444444444444444444444444444444444444444444444444444444444'
);
SQL
then
  echo 'tenant B unexpectedly advanced tenant A witness checkpoint' >&2
  rm -f "$unauthorized_witness_output"
  exit 1
fi
if ! grep -Fq 'not authorized for session login gate_tenant_b' "$unauthorized_witness_output"; then
  echo 'cross-tenant witness advance failed for an unexpected reason' >&2
  cat "$unauthorized_witness_output" >&2
  rm -f "$unauthorized_witness_output"
  exit 1
fi
rm -f "$unauthorized_witness_output"

witness_b="$(psql_as gate_tenant_b 'gate-isolation-tenant-b' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT accepted::text || ':' || coalesce(reason, '')
FROM emilia_gate_evidence.advance_network_witness_checkpoint(
  'tenant-b', 'gate-b',
  decode('7769746e6573733a656467652d3200636170747572653a62', 'hex'), 1,
  'sha256:5555555555555555555555555555555555555555555555555555555555555555'
);
SQL
)"
if [[ "$witness_b" != 'true:' ]]; then
  echo "tenant B witness advance did not succeed: $witness_b" >&2
  exit 1
fi

tenant_a_rows="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT count(*) FROM emilia_gate_evidence.records;
SQL
)"
tenant_b_rows="$(psql_as gate_tenant_b 'gate-isolation-tenant-b' --quiet --tuples-only --no-align <<'SQL'
SET ROLE emilia_gate_evidence_runtime;
SELECT count(*) FROM emilia_gate_evidence.records;
SQL
)"
owner_rows="$(psql_as gate_migrator 'gate-isolation-migrator' --quiet --tuples-only --no-align \
  --command='SELECT count(*) FROM emilia_gate_evidence.records')"
witness_a_rows="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align \
  --command='SELECT count(*) FROM emilia_gate_evidence.network_witness_checkpoints')"
witness_b_rows="$(psql_as gate_tenant_b 'gate-isolation-tenant-b' --quiet --tuples-only --no-align \
  --command='SELECT count(*) FROM emilia_gate_evidence.network_witness_checkpoints')"
owner_witness_rows="$(psql_as gate_migrator 'gate-isolation-migrator' --quiet --tuples-only --no-align \
  --command='SELECT count(*) FROM emilia_gate_evidence.network_witness_checkpoints')"

if [[ "$tenant_a_rows" != '1' || "$tenant_b_rows" != '1' || "$owner_rows" != '2' ]]; then
  echo "RLS row counts were unexpected: tenant_a=$tenant_a_rows tenant_b=$tenant_b_rows owner=$owner_rows" >&2
  exit 1
fi
if [[ "$witness_a_rows" != '2' || "$witness_b_rows" != '1' || "$owner_witness_rows" != '3' ]]; then
  echo "witness RLS row counts were unexpected: tenant_a=$witness_a_rows tenant_b=$witness_b_rows owner=$owner_witness_rows" >&2
  exit 1
fi

rls_flags="$(psql_as gate_migrator 'gate-isolation-migrator' --quiet --tuples-only --no-align <<'SQL'
SELECT string_agg(relrowsecurity::text || ':' || relforcerowsecurity::text, ',' ORDER BY relname)
FROM pg_catalog.pg_class
WHERE oid IN (
  'emilia_gate_evidence.heads'::regclass,
  'emilia_gate_evidence.records'::regclass,
  'emilia_gate_evidence.network_witness_checkpoints'::regclass
);
SQL
)"
if [[ "$rls_flags" != 'true:true,true:true,true:true' ]]; then
  echo "runtime tables did not enable and force RLS: $rls_flags" >&2
  exit 1
fi

runtime_privileges="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align <<'SQL'
SELECT concat_ws(':',
  has_table_privilege(current_user, 'emilia_gate_evidence.records', 'SELECT'),
  has_table_privilege(current_user, 'emilia_gate_evidence.records', 'INSERT'),
  has_table_privilege(current_user, 'emilia_gate_evidence.runtime_scope_grants', 'SELECT'),
  has_table_privilege(current_user, 'emilia_gate_evidence.network_witness_scope_grants', 'SELECT'),
  has_table_privilege(current_user, 'emilia_gate_evidence.network_witness_checkpoints', 'INSERT'),
  has_function_privilege(
    current_user,
    'emilia_gate_evidence.grant_runtime_scope(name,text,text,text)',
    'EXECUTE'
  ),
  has_function_privilege(
    current_user,
    'emilia_gate_evidence.advance_network_witness_checkpoint(text,text,bytea,bigint,text)',
    'EXECUTE'
  )
);
SQL
)"
if [[ "$runtime_privileges" != 't:f:f:f:f:f:t' ]]; then
  echo "runtime privilege split was unexpected: $runtime_privileges" >&2
  exit 1
fi

psql_as gate_migrator 'gate-isolation-migrator' --quiet >/dev/null <<'SQL'
SELECT emilia_gate_evidence.revoke_runtime_scope(
  'gate_tenant_a', 'tenant-a', 'gate-a', 'stream-a'
);
SELECT emilia_gate_evidence.revoke_network_witness_scope(
  'gate_tenant_a',
  'tenant-a',
  'gate-a',
  decode('7769746e6573733a656467652d3100636170747572653a61', 'hex')
);
SELECT emilia_gate_evidence.revoke_network_witness_scope(
  'gate_tenant_a',
  'tenant-a',
  'gate-a',
  decode('7769746e6573733a656467652d3300636170747572653a72616365', 'hex')
);
SQL
tenant_a_after_revoke="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align \
  --command='SELECT count(*) FROM emilia_gate_evidence.records')"
tenant_a_witness_after_revoke="$(psql_as gate_tenant_a 'gate-isolation-tenant-a' --quiet --tuples-only --no-align \
  --command='SELECT count(*) FROM emilia_gate_evidence.network_witness_checkpoints')"
if [[ "$tenant_a_after_revoke" != '0' || "$tenant_a_witness_after_revoke" != '0' ]]; then
  echo "revoked tenant A scope remained readable: evidence=$tenant_a_after_revoke witness=$tenant_a_witness_after_revoke" >&2
  exit 1
fi

echo 'Live Postgres two-login evidence and network-witness isolation passed'
