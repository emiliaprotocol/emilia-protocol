-- Local E2E role split: migrations run as gate_owner; the service connects as
-- gate_runtime. The runtime can mutate replay/action state and can append
-- evidence only through the SECURITY DEFINER function installed by
-- packages/gate/deploy/sql/001-runtime.sql.

\set ON_ERROR_STOP on

SELECT format(
  'CREATE ROLE gate_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION PASSWORD %L',
  :'runtime_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'gate_runtime')
\gexec

ALTER ROLE gate_runtime
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION;
SELECT format('ALTER ROLE gate_runtime PASSWORD %L', :'runtime_password')
\gexec

GRANT CONNECT ON DATABASE gate_e2e TO gate_runtime;
GRANT USAGE ON SCHEMA public TO gate_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ep_gate_consumption TO gate_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE ep_gate_actions TO gate_runtime;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE ep_gate_actions FROM gate_runtime;

GRANT emilia_gate_evidence_runtime TO gate_runtime;
SELECT emilia_gate_evidence.grant_runtime_scope(
  'gate_runtime',
  'gate-e2e-tenant',
  'gate-e2e-service',
  'gate-e2e'
);
