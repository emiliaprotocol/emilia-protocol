#!/usr/bin/env bash
set -euo pipefail

sql_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/001-runtime.sql"

assert_sql() {
  local pattern="$1"
  local description="$2"
  if ! grep -Eq -- "$pattern" "$sql_file"; then
    echo "SQL contract assertion failed: $description" >&2
    exit 1
  fi
}

assert_sql 'CREATE TABLE IF NOT EXISTS emilia_gate_evidence\.runtime_scope_grants' \
  'runtime login scope bindings must be owner-managed in Postgres'
assert_sql 'g\.login_role = session_user' \
  'scope authorization must bind the authenticated login, not SET ROLE state'
assert_sql 'NOT r\.rolsuper' 'scope grants must reject superuser logins'
assert_sql 'NOT r\.rolbypassrls' 'scope grants must reject BYPASSRLS logins'
assert_sql 'ALTER TABLE emilia_gate_evidence\.heads ENABLE ROW LEVEL SECURITY' \
  'heads must enable RLS'
assert_sql 'ALTER TABLE emilia_gate_evidence\.heads FORCE ROW LEVEL SECURITY' \
  'heads must force RLS'
assert_sql 'ALTER TABLE emilia_gate_evidence\.records ENABLE ROW LEVEL SECURITY' \
  'records must enable RLS'
assert_sql 'ALTER TABLE emilia_gate_evidence\.records FORCE ROW LEVEL SECURITY' \
  'records must force RLS'
assert_sql 'CREATE POLICY evidence_heads_runtime_read' \
  'heads must have a runtime read policy'
assert_sql 'CREATE POLICY evidence_records_runtime_read' \
  'records must have a runtime read policy'
assert_sql 'IF NOT emilia_gate_evidence\.runtime_scope_authorized\(' \
  'SECURITY DEFINER append must authorize its requested scope'
assert_sql "ERRCODE = '42501'" 'unauthorized append must raise insufficient_privilege'
assert_sql 'REVOKE ALL ON TABLE emilia_gate_evidence\.runtime_scope_grants' \
  'runtime roles must not read or modify scope bindings'
assert_sql 'CREATE TABLE IF NOT EXISTS emilia_gate_evidence\.network_witness_checkpoints' \
  'network-witness checkpoints must be durable and tenant scoped'
assert_sql 'stream_key[[:space:]]+BYTEA NOT NULL' \
  'network-witness stream keys must preserve embedded NUL separators'
assert_sql 'PRIMARY KEY \(tenant_id, gate_id, stream_key\)' \
  'network-witness checkpoints must serialize each exact binary scope'
assert_sql 'CREATE TABLE IF NOT EXISTS emilia_gate_evidence\.network_witness_scope_grants' \
  'network-witness binary scopes must be bound to runtime logins'
assert_sql 'CREATE OR REPLACE FUNCTION emilia_gate_evidence\.advance_network_witness_checkpoint' \
  'runtime SQL must expose atomic witness checkpoint advancement'
assert_sql 'advance_network_witness_checkpoint\(TEXT, TEXT, BYTEA, BIGINT, TEXT\)' \
  'witness advancement must accept exact binary stream keys'
assert_sql "'statement_replay'::TEXT" 'witness advancement must distinguish replay'
assert_sql "'sequence_rollback'::TEXT" 'witness advancement must distinguish rollback'
assert_sql "'sequence_equivocation'::TEXT" \
  'witness advancement must distinguish same-sequence equivocation'
assert_sql 'equivocated[[:space:]]+BOOLEAN NOT NULL DEFAULT FALSE' \
  'network-witness checkpoints must persist equivocation state'
assert_sql 'SET equivocated = TRUE' \
  'same-sequence conflicts must poison the durable witness stream'
assert_sql 'IF v_equivocated THEN' \
  'a poisoned witness stream must remain closed on later sequences'
assert_sql 'ALTER TABLE emilia_gate_evidence\.network_witness_checkpoints FORCE ROW LEVEL SECURITY' \
  'network-witness checkpoint reads must force RLS'
assert_sql "EMILIA network-witness scope is not authorized for session login %'.*session_user" \
  'witness advancement must authorize session_user scope'

if grep -Eiq 'GRANT[[:space:]]+(INSERT|UPDATE|DELETE|TRUNCATE)' "$sql_file"; then
  echo 'SQL contract assertion failed: runtime SQL must not grant direct evidence writes' >&2
  exit 1
fi

echo 'Postgres evidence SQL contract assertions passed'
